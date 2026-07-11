//! Integration tests for the worker spawn layer (`spawn.rs`):
//!
//! - **AC-19** — the `claude-sandbox` store-path pin guard refuses (and returns
//!   the typed error) when the `claude-sandbox` resolved on PATH is a shim at a
//!   *different* path than the pinned nix store path, and accepts when the
//!   resolved path IS the pinned path. No live claude is involved.
//! - **AC-27** — a direct worker command is hosted in a zellij pane named
//!   `<role>-<issue>-r<round>`; the pane is alive while the worker runs and
//!   closes on exit (mirrors `crates/zellij_host/tests/spawn.rs`).
//! - **Env hygiene** — a direct worker is dispatched with an orchestrator-side
//!   secret in the environment; the worker dumps its env and the secret is
//!   proven absent (scrubbed) while the explicit allowlist is present.
//! - **Dogfood dispatch** — `fake-implementer.sh` dispatched as a direct
//!   command into a `WorkspaceManager::prepare`d workspace runs to completion
//!   and leaves `_orchestrator/DONE`, so S3's `DoneSentinel::verify` succeeds.
//!   This is the end-to-end proof the build pump (#15) relies on for AC-11a.
//!
//! These tests drive the real zellij / jj / crosslink CLIs through the test
//! harness (the AC-24 no-shell-out lint scopes to `src/**` only), and stand up
//! a process-unique zellij session so a real `vdd-orchestrator` session and
//! concurrent runs are never disturbed.

mod common;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use orchestrator::artifacts::DoneSentinel;
use orchestrator::spawn::{ClaudeSpawn, SandboxPin, SpawnOutcome, Spawner, WorkerCommand};
use orchestrator::state::{Phase, WorkerRole};
use orchestrator::workspace::{PreparedWorkspace, WorkspaceManager, WorkspaceName};
use vetinari_error::SpawnError;
use vetinari_zellij_host::{session_ensure, SessionHandle};

use common::{build_fixture, fake_implementer, Fixture};

/// Serializes every zellij-hosted test in this binary. The `zellij` CLI in this
/// env shares one background server + socket across all sessions; running
/// `new-pane` / `list-panes` / `kill-session` from several test threads at once
/// races (a concurrent `list-panes --json` can momentarily return empty during
/// another test's teardown). Cargo runs integration tests multithreaded, so a
/// process-wide lock — held for the whole test, released after cleanup — keeps
/// each zellij-touching test's view of the server consistent.
static ZELLIJ_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Kills the test's zellij session on drop, so a failed assertion still cleans
/// up, then releases the shared [`ZELLIJ_LOCK`] (dropped after the kill because
/// `_zellij` is declared after `name` — fields drop in declaration order).
/// Mirrors `zellij_host/tests/spawn.rs`.
struct SessionGuard {
    name: String,
    _zellij: std::sync::MutexGuard<'static, ()>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let _ = Command::new("zellij")
            .args(["kill-session", &self.name])
            .output();
    }
}

/// Create a unique headless zellij session, taking the shared [`ZELLIJ_LOCK`]
/// for the lifetime of the returned guard so this test is the sole driver of
/// the zellij server while it runs. The name mixes the pid with a monotonic
/// counter so sessions never alias across tests.
fn unique_session(tag: &str) -> (SessionHandle, SessionGuard) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let held = ZELLIJ_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("vetinari-{tag}-{}-{n}", std::process::id());
    let guard = SessionGuard {
        name: name.clone(),
        _zellij: held,
    };
    let session = session_ensure(&name).expect("ensure headless session");
    (session, guard)
}

/// Write an executable shim script at `dir/name` and return `dir` so the caller
/// can prepend it to PATH.
fn write_shim(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write shim");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).expect("stat shim").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod shim");
    }
}

/// Prepend `dir` to PATH for the duration of `f`, restoring it afterward.
///
/// Serialized through a global mutex: PATH is process-global, and Rust's test
/// harness runs tests on multiple threads. Poison is recovered so one failing
/// test doesn't wedge the rest.
fn with_path_prefix<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    use std::sync::Mutex;
    static PATH_LOCK: Mutex<()> = Mutex::new(());
    let _held = PATH_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let original = std::env::var_os("PATH");
    let mut entries = vec![dir.to_path_buf()];
    if let Some(orig) = &original {
        entries.extend(std::env::split_paths(orig));
    }
    let joined = std::env::join_paths(entries).expect("join PATH");
    // SAFETY: guarded by PATH_LOCK; no other thread mutates PATH concurrently.
    unsafe { std::env::set_var("PATH", &joined) };
    let out = f();
    // SAFETY: same guard; restore the original value (or clear if it was unset).
    unsafe {
        match original {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }
    out
}

/// Prepare a fresh worker workspace in `fixture` for `role`/`round`, returning
/// the manager (hold it) and the prepared workspace.
fn prepare_workspace(
    fixture: &Fixture,
    phase: Phase,
    role_issue: &str,
    round: u32,
) -> (WorkspaceManager, PreparedWorkspace) {
    let manager = WorkspaceManager::load(&fixture.root).expect("load workspace manager");
    let name = WorkspaceName::generate(phase, role_issue, round);
    let prepared = manager.prepare(&name, "main").expect("prepare workspace");
    (manager, prepared)
}

// ============================================================================
// AC-19 — store-path pin guard: a shim at a different path fails; the real
// resolved path passes
// ============================================================================

#[test]
fn ac19_pin_guard_refuses_shim_at_a_different_path() {
    // The pinned "real" binary lives at one path; a `claude-sandbox` shim at a
    // DIFFERENT path is what PATH resolves to. Store-path identity ⇒ refuse.
    let real_dir = tempfile::tempdir().expect("real dir");
    write_shim(
        real_dir.path(),
        "claude-sandbox",
        "#!/usr/bin/env bash\nexit 0\n",
    );
    let pinned = real_dir.path().join("claude-sandbox");

    let shim_dir = tempfile::tempdir().expect("shim dir");
    write_shim(
        shim_dir.path(),
        "claude-sandbox",
        "#!/usr/bin/env bash\nexit 0\n",
    );

    let pin = SandboxPin::new(pinned.to_string_lossy().into_owned());
    let err = with_path_prefix(shim_dir.path(), || pin.verify()).unwrap_err();

    match err {
        SpawnError::ClaudeSandboxVersionMismatch { expected, found } => {
            assert_eq!(expected, pinned.to_string_lossy());
            assert!(
                found.contains("claude-sandbox"),
                "found should carry the resolved shim path, got {found:?}"
            );
            assert_ne!(found, expected, "the shim must resolve to a DIFFERENT path");
        }
        other => panic!("expected ClaudeSandboxVersionMismatch, got {other:?}"),
    }
}

#[test]
fn ac19_pin_guard_accepts_the_real_resolved_path() {
    // When the `claude-sandbox` on PATH IS the pinned store path, verify passes.
    let dir = tempfile::tempdir().expect("dir");
    write_shim(
        dir.path(),
        "claude-sandbox",
        "#!/usr/bin/env bash\nexit 0\n",
    );
    let pinned = dir.path().join("claude-sandbox");

    let pin = SandboxPin::new(pinned.to_string_lossy().into_owned());
    let result = with_path_prefix(dir.path(), || pin.verify());
    assert!(
        result.is_ok(),
        "the exact pinned path resolved on PATH must verify, got {result:?}"
    );
}

#[test]
fn ac19_empty_pin_fails_closed() {
    // An unset pin must never accept-all, regardless of what's on PATH.
    let dir = tempfile::tempdir().expect("dir");
    write_shim(
        dir.path(),
        "claude-sandbox",
        "#!/usr/bin/env bash\nexit 0\n",
    );
    let pin = SandboxPin::new("");
    let err = with_path_prefix(dir.path(), || pin.verify()).unwrap_err();
    assert!(
        matches!(err, SpawnError::ClaudeSandboxMissing { .. }),
        "empty pin must fail closed, got {err:?}"
    );
}

#[test]
fn ac19_spawn_refuses_claude_worker_on_mismatch_without_creating_a_pane() {
    let fixture = build_fixture();
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::Implementing, "42", 0);

    let (session, _guard) = unique_session("ac19");
    // Pin to a "real" path that PATH will NOT resolve to.
    let real_dir = tempfile::tempdir().expect("real dir");
    write_shim(
        real_dir.path(),
        "claude-sandbox",
        "#!/usr/bin/env bash\nexit 0\n",
    );
    let pinned = real_dir.path().join("claude-sandbox");
    let pin = SandboxPin::new(pinned.to_string_lossy().into_owned());
    let spawner = Spawner::new(session, &fixture.root, pin);

    // A shim at a different path is what PATH resolves to.
    let shim_dir = tempfile::tempdir().expect("shim dir");
    write_shim(
        shim_dir.path(),
        "claude-sandbox",
        "#!/usr/bin/env bash\nexit 0\n",
    );

    let command = WorkerCommand::Claude(ClaudeSpawn {
        role: WorkerRole::Implementer,
        task: "irrelevant — the spawn must refuse first".into(),
        allowlist: "Read".into(),
        system_prompt: "You are the Implementer.".into(),
        max_turns: 80,
        mounts: orchestrator::spawn::MountMatrix::for_role(
            WorkerRole::Implementer,
            &fixture.root,
            prepared.path(),
        ),
    });

    let result = with_path_prefix(shim_dir.path(), || {
        spawner.spawn(WorkerRole::Implementer, "42", 0, &prepared, &command)
    });

    assert!(
        matches!(result, Err(SpawnError::ClaudeSandboxVersionMismatch { .. })),
        "a real spawn must refuse on a store-path mismatch, got {result:?}"
    );
}

// ============================================================================
// AC-27 — a direct worker command is hosted in a named, self-closing pane
// ============================================================================

#[test]
fn ac27_direct_command_hosted_in_named_pane_that_closes_on_exit() {
    let fixture = build_fixture();
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::Implementing, "9999", 0);

    let (session, _guard) = unique_session("ac27");
    let session_name = session.name.clone();
    let spawner = Spawner::new(session, &fixture.root, SandboxPin::new("unused-direct"));

    // A trivial direct command that writes a marker (proving env reached it)
    // and then runs long enough to be observed alive.
    let command = WorkerCommand::direct(
        [
            "sh",
            "-c",
            "printf %s \"$VETINARI_MARK\" > marker.txt; sleep 3",
        ],
        [("VETINARI_MARK", "applied")],
    );

    let handle = spawner
        .spawn(WorkerRole::Implementer, "9999", 0, &prepared, &command)
        .expect("spawn direct worker");

    // The pane is named exactly `<role>-<issue>-r<round>`.
    assert_eq!(handle.pane.name, "implementer-9999-r0");
    assert_eq!(handle.pane.session, session_name);

    // Alive while the worker's `sleep` runs. Retry a couple times to ride out a
    // transient `list-panes` hiccup from the shared zellij server.
    let mut alive = false;
    for _ in 0..5 {
        match vetinari_zellij_host::pane_alive(&handle.pane) {
            Ok(v) => {
                alive = v;
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    assert!(alive, "pane should be alive while the direct worker runs");

    // Waiting past the sleep observes a clean exit (the pane closed itself).
    let outcome = handle
        .wait(Duration::from_secs(20), Duration::from_millis(300))
        .expect("wait for worker");
    assert_eq!(outcome, SpawnOutcome::Exited);

    // The env-supplied marker reached the worker process (env was applied).
    let marker = prepared.path().join("marker.txt");
    assert_eq!(
        std::fs::read_to_string(&marker).ok().as_deref(),
        Some("applied"),
        "direct worker should have seen VETINARI_MARK from env"
    );
}

#[test]
fn ac27_wait_reports_still_running_before_worker_exits() {
    let fixture = build_fixture();
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::Implementing, "1", 0);

    let (session, _guard) = unique_session("ac27b");
    let spawner = Spawner::new(session, &fixture.root, SandboxPin::new("unused"));

    let command = WorkerCommand::direct(["sh", "-c", "sleep 5"], Vec::<(&str, &str)>::new());
    let handle = spawner
        .spawn(WorkerRole::Adversary, "1", 0, &prepared, &command)
        .expect("spawn");

    // A short wait times out with the worker still running.
    let outcome = handle
        .wait(Duration::from_millis(300), Duration::from_millis(100))
        .expect("wait");
    assert_eq!(outcome, SpawnOutcome::StillRunning);

    // Cleanup: close the pane so the session guard's kill is unambiguous.
    handle.close();
}

// ============================================================================
// Env hygiene — orchestrator secrets are scrubbed from the worker's env
// ============================================================================

#[test]
fn worker_env_is_scrubbed_of_orchestrator_secrets() {
    use std::sync::Mutex;
    // PATH + the secret env var are process-global; serialize with the same
    // discipline as `with_path_prefix`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _held = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let fixture = build_fixture();
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::Implementing, "7", 0);

    let (session, _guard) = unique_session("envscrub");
    let spawner = Spawner::new(session, &fixture.root, SandboxPin::new("unused-direct"));

    // A fake orchestrator secret in THIS process's environment. The worker must
    // NOT see it (env hygiene): `env -i` clears the inherited environment.
    // SAFETY: guarded by ENV_LOCK; no other thread mutates env concurrently.
    unsafe { std::env::set_var("VETINARI_FAKE_SECRET", "top-secret-token") };

    // The worker dumps its full environment to a file, then exits.
    let command = WorkerCommand::direct(
        ["sh", "-c", "env > env_dump.txt"],
        [("VETINARI_EXPLICIT", "provided")],
    );

    let handle = spawner
        .spawn(WorkerRole::Implementer, "7", 0, &prepared, &command)
        .expect("spawn env-dump worker");

    let outcome = handle
        .wait(Duration::from_secs(20), Duration::from_millis(300))
        .expect("wait for env-dump worker");
    assert_eq!(outcome, SpawnOutcome::Exited);

    // SAFETY: same guard; clean up the fake secret.
    unsafe { std::env::remove_var("VETINARI_FAKE_SECRET") };

    let dump = std::fs::read_to_string(prepared.path().join("env_dump.txt"))
        .expect("worker should have written its env dump");

    // The orchestrator secret was scrubbed.
    assert!(
        !dump.contains("VETINARI_FAKE_SECRET"),
        "orchestrator secret leaked into worker env:\n{dump}"
    );
    assert!(
        !dump.contains("top-secret-token"),
        "orchestrator secret VALUE leaked into worker env:\n{dump}"
    );
    // The explicit Direct env reached the worker.
    assert!(
        dump.contains("VETINARI_EXPLICIT=provided"),
        "explicit Direct env should be present:\n{dump}"
    );
    // The minimal allowlist reached the worker (PATH is needed to find `env`).
    assert!(
        dump.lines().any(|l| l.starts_with("PATH=")),
        "allowlisted PATH should be present:\n{dump}"
    );
}

// ============================================================================
// Dogfood dispatch — fake-implementer → DONE (the AC-11a tracer bullet)
// ============================================================================

#[test]
fn dogfood_fake_implementer_runs_to_done_in_prepared_workspace() {
    let fixture = build_fixture();
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::Implementing, "42", 0);

    let (session, _guard) = unique_session("dogfood");
    let spawner = Spawner::new(session, &fixture.root, SandboxPin::new("unused-direct"));

    // Dispatch the committed fake worker as a DIRECT command into the prepared
    // workspace — exactly what the build pump does for the AC-11a dogfood.
    let script = fake_implementer();
    let command = WorkerCommand::direct(
        ["bash".to_owned(), script.to_string_lossy().into_owned()],
        Vec::<(String, String)>::new(),
    );

    let handle = spawner
        .spawn(WorkerRole::Implementer, "42", 0, &prepared, &command)
        .expect("spawn fake implementer");
    assert_eq!(handle.pane.name, "implementer-42-r0");

    let outcome = handle
        .wait(Duration::from_secs(60), Duration::from_millis(300))
        .expect("wait for fake implementer");
    assert_eq!(
        outcome,
        SpawnOutcome::Exited,
        "the fake implementer must run to completion"
    );

    // The worker wrote _orchestrator/DONE last (REQ-3b), so S3's DoneSentinel
    // verification succeeds against the workspace — the pump's success signal.
    let done = DoneSentinel::verify(prepared.path())
        .expect("fake implementer must leave a verifiable DONE sentinel");
    assert_eq!(
        done.exit_status(),
        orchestrator::artifacts::ExitStatus::Success
    );
    // It declared its result.md artifact, verified by sha256.
    assert!(
        done.sha_for("_orchestrator/result.md").is_some(),
        "DONE must list the result.md artifact it wrote"
    );

    // And it actually committed its change via `jj describe` (the workspace's
    // working copy is no longer empty).
    let diff = Command::new("jj")
        .args(["diff", "--name-only"])
        .current_dir(prepared.path())
        .output()
        .expect("jj diff");
    assert!(
        String::from_utf8_lossy(&diff.stdout).contains("src/lib.rs"),
        "the fake implementer should have edited src/lib.rs"
    );
}
