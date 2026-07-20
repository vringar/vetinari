//! Integration tests for the worker spawn layer (`spawn.rs`):
//!
//! - **AC-19** — the `bwrap` store-path pin guard refuses (and returns the
//!   typed error) when the `bwrap` resolved on PATH is a shim at a *different*
//!   path than the pinned nix store path, and accepts when the resolved path IS
//!   the pinned path. No live claude is involved.
//! - **AC-4/AC-5/AC-6 (REAL isolation)** — actually invoke `bwrap` with the argv
//!   **derived from the production `ClaudeSpawn::bwrap_prefix`** (the same
//!   base-mounts + matrix rendering `to_argv` uses, so a regression in
//!   `base_mounts`/`to_argv` is caught here — finding #4), wrapping a shell
//!   probe against a real fixture repo, and assert the kernel mount namespace
//!   enforces the matrix: the Adversary can see neither the *repository* `.jj/`,
//!   `.git/`, nor `.orchestrator/` (though its jj *workspace* still carries its
//!   own `<workspace>/.jj` — finding #3) while it can see the workspace (RW) and
//!   `.crosslink/` (RO); the Implementer sees `.jj/` **and** the colocated
//!   `.git/` (both RW, finding #1) but still not `.orchestrator/`, and can
//!   actually run `jj status`/`jj log` inside its namespace.
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
//! These tests drive the real zellij / jj / crosslink / bwrap CLIs through the
//! test harness (the AC-24 no-shell-out lint scopes to `src/**` only), and stand
//! up a process-unique zellij session so a real `vdd-orchestrator` session and
//! concurrent runs are never disturbed.

mod common;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use orchestrator::artifacts::DoneSentinel;
use orchestrator::spawn::{
    ClaudeSpawn, SandboxHost, SandboxPin, SpawnOutcome, Spawner, WorkerCommand,
};
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
// AC-19 — store-path pin guard: a `bwrap` shim at a different path fails; the
// real resolved path passes
// ============================================================================

#[test]
fn ac19_pin_guard_refuses_shim_at_a_different_path() {
    // The pinned "real" bwrap lives at one path; a `bwrap` shim at a DIFFERENT
    // path is what PATH resolves to. Store-path identity ⇒ refuse.
    let real_dir = tempfile::tempdir().expect("real dir");
    write_shim(real_dir.path(), "bwrap", "#!/usr/bin/env bash\nexit 0\n");
    let pinned = real_dir.path().join("bwrap");

    let shim_dir = tempfile::tempdir().expect("shim dir");
    write_shim(shim_dir.path(), "bwrap", "#!/usr/bin/env bash\nexit 0\n");

    let pin = SandboxPin::new(pinned.to_string_lossy().into_owned());
    let err = with_path_prefix(shim_dir.path(), || pin.verify()).unwrap_err();

    match err {
        SpawnError::BwrapPinMismatch { expected, found } => {
            assert_eq!(expected, pinned.to_string_lossy());
            assert!(
                found.contains("bwrap"),
                "found should carry the resolved shim path, got {found:?}"
            );
            assert_ne!(found, expected, "the shim must resolve to a DIFFERENT path");
        }
        other => panic!("expected BwrapPinMismatch, got {other:?}"),
    }
}

#[test]
fn ac19_pin_guard_accepts_the_real_resolved_path() {
    // When the `bwrap` on PATH IS the pinned store path, verify passes.
    let dir = tempfile::tempdir().expect("dir");
    write_shim(dir.path(), "bwrap", "#!/usr/bin/env bash\nexit 0\n");
    let pinned = dir.path().join("bwrap");

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
    write_shim(dir.path(), "bwrap", "#!/usr/bin/env bash\nexit 0\n");
    let pin = SandboxPin::new("");
    let err = with_path_prefix(dir.path(), || pin.verify()).unwrap_err();
    assert!(
        matches!(err, SpawnError::BwrapMissing { .. }),
        "empty pin must fail closed, got {err:?}"
    );
}

#[test]
fn ac19_spawn_refuses_claude_worker_on_mismatch_without_creating_a_pane() {
    let fixture = build_fixture();
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::Implementing, "42", 0);

    let (session, _guard) = unique_session("ac19");
    // Pin to a "real" bwrap path that PATH will NOT resolve to.
    let real_dir = tempfile::tempdir().expect("real dir");
    write_shim(real_dir.path(), "bwrap", "#!/usr/bin/env bash\nexit 0\n");
    let pinned = real_dir.path().join("bwrap");
    let pin = SandboxPin::new(pinned.to_string_lossy().into_owned());
    let spawner = Spawner::new(session, &fixture.root, pin);

    // A shim at a different path is what PATH resolves to.
    let shim_dir = tempfile::tempdir().expect("shim dir");
    write_shim(shim_dir.path(), "bwrap", "#!/usr/bin/env bash\nexit 0\n");

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
        matches!(result, Err(SpawnError::BwrapPinMismatch { .. })),
        "a real spawn must refuse on a store-path mismatch, got {result:?}"
    );
}

#[test]
fn claude_spawn_errors_cleanly_when_workspace_has_no_shell_nix() {
    // The `hello` fixture ships no shell.nix, so the real (claude) path must
    // fail with a typed ShellNixMissing — never an opaque bwrap/nix-shell crash
    // deep inside the sandbox (finding #5). We pin to the real `bwrap` on PATH
    // so the store-path guard PASSES and execution reaches the shell.nix check.
    let fixture = build_fixture();
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::Implementing, "42", 0);
    assert!(
        !prepared.path().join("shell.nix").exists(),
        "the hello fixture must have no shell.nix for this test to be meaningful"
    );

    let (session, _guard) = unique_session("shellnix");
    let spawner = Spawner::new(session, &fixture.root, SandboxPin::new(resolve_bwrap()));

    let command = WorkerCommand::claude(
        WorkerRole::Implementer,
        &fixture.root,
        prepared.path(),
        "task body",
        "Read",
        "You are the Implementer.",
        80,
    );

    let result = spawner.spawn(WorkerRole::Implementer, "42", 0, &prepared, &command);
    assert!(
        matches!(result, Err(SpawnError::ShellNixMissing { .. })),
        "a claude spawn into a shell.nix-less workspace must fail typed, got {result:?}"
    );
    // And it failed BEFORE delivering the task (no partial artifact left behind).
    assert!(
        !prepared.path().join("_orchestrator/task.md").exists(),
        "task.md must not be written when the spawn fails the shell.nix precheck"
    );
}

// ============================================================================
// AC-4 / AC-5 / AC-6 — REAL isolation: the rendered per-role mount matrix is
// enforced by a live nested `bwrap`, not merely documented.
// ============================================================================

/// Resolve the live `bwrap` for the isolation tests: the shell's `VDD_BWRAP_PIN`
/// if set, else the first `bwrap` on PATH. Returned as a string so it can seed a
/// [`SandboxPin`].
fn resolve_bwrap() -> String {
    if let Some(pin) = std::env::var("VDD_BWRAP_PIN")
        .ok()
        .filter(|p| !p.is_empty())
    {
        return pin;
    }
    let path_env = std::env::var("PATH").unwrap_or_default();
    std::env::split_paths(&path_env)
        .map(|d| d.join("bwrap"))
        .find(|p| p.exists())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "bwrap".to_owned())
}

/// Build the **real** [`SandboxHost`] the production spawn path would, from the
/// live environment (the resolved `bwrap`, the real `$HOME`, nix profile, etc.).
/// Using [`SandboxHost::resolve`] — not a hand-built host — is what gives the
/// isolation tests live coverage of `base_mounts` discovery (finding #4).
fn live_host() -> SandboxHost {
    let pin = SandboxPin::new(resolve_bwrap());
    SandboxHost::resolve(&pin)
        .expect("resolve live sandbox host (HOME + nix-shell must be present)")
}

/// The `ClaudeSpawn` for `role` against the fixture — the exact struct the
/// production path builds, so its `bwrap_prefix` renders the production argv.
fn claude_spawn(role: WorkerRole, root: &Path, workspace: &Path) -> ClaudeSpawn {
    match WorkerCommand::claude(
        role,
        root,
        workspace,
        "probe task",
        "Read",
        "probe prompt",
        1,
    ) {
        WorkerCommand::Claude(s) => s,
        _ => unreachable!("WorkerCommand::claude yields the Claude arm"),
    }
}

/// Assemble the live bwrap argv for a `role` probe by appending `-- /bin/sh -c
/// <script>` to the production [`ClaudeSpawn::bwrap_prefix`] (bwrap bin + real
/// `base_mounts` + rendered matrix). `/bin/sh` is the symlink `base_mounts`
/// installs, so this exercises the real base policy end to end (finding #4).
fn probe_argv(role: WorkerRole, root: &Path, workspace: &Path, script: &str) -> Vec<String> {
    let host = live_host();
    let mut args = claude_spawn(role, root, workspace).bwrap_prefix(workspace, &host);
    args.push("--".into());
    args.push("/bin/sh".into());
    args.push("-c".into());
    args.push(script.to_owned());
    args
}

/// Run a live nested `bwrap` for `role` with the production-derived argv, and
/// return the probe's stdout. Asserts the sandbox came up and the probe ran to
/// completion.
fn run_role_probe(role: WorkerRole, root: &Path, workspace: &Path) -> String {
    // The probe checks ABSOLUTE fixture paths (the matrix binds the repository
    // `.jj/`/`.git/` and `.crosslink/` at `<root>/…`), plus the workspace's OWN
    // `.jj` (finding #3), using only shell builtins so no external binary is
    // needed.
    let r = root.to_string_lossy();
    let ws = workspace.to_string_lossy();
    let script = format!(
        r#"
probe() {{ if [ -e "$1" ]; then echo "$2=PRESENT"; else echo "$2=ABSENT"; fi; }}
probe "{r}/.jj" JJ
probe "{r}/.git" GIT
probe "{r}/.orchestrator" ORCH
probe "{r}/.crosslink" CROSS
probe "{ws}" WS
probe "{ws}/.jj" WSJJ
if (echo x > "{r}/.crosslink/.vetinari_probe") 2>/dev/null; then echo CROSS_RW; rm -f "{r}/.crosslink/.vetinari_probe"; else echo CROSS_RO; fi
if (echo x > "{ws}/.vetinari_probe") 2>/dev/null; then echo WS_RW; rm -f "{ws}/.vetinari_probe"; else echo WS_RO; fi
if [ -e "{r}/.jj" ]; then
  if (echo x > "{r}/.jj/.vetinari_probe") 2>/dev/null; then echo JJ_RW; rm -f "{r}/.jj/.vetinari_probe"; else echo JJ_RO; fi
fi
echo DONE
"#
    );

    let args = probe_argv(role, root, workspace, &script);
    let out = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("failed to invoke bwrap `{}`: {e}", args[0]));
    assert!(
        out.status.success(),
        "nested bwrap failed ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains("DONE"),
        "probe did not run to completion:\n{stdout}"
    );
    stdout
}

/// Make sure the fixture actually has the dirs we assert are hidden, so an
/// ABSENT result proves the mount policy excludes them (not that they never
/// existed on the host). The fixture is jj-colocated, so `.jj/` and `.git/`
/// already exist; `.orchestrator/` we create.
fn ensure_isolation_dirs(root: &Path) {
    std::fs::create_dir_all(root.join(".orchestrator")).expect("mk .orchestrator");
    std::fs::write(root.join(".orchestrator/state.db"), b"sentinel").expect("seed .orchestrator");
    assert!(root.join(".jj").is_dir(), "fixture must have .jj/");
    assert!(root.join(".git").is_dir(), "fixture must have .git/");
    assert!(
        root.join(".crosslink").is_dir(),
        "fixture must have .crosslink/"
    );
}

#[test]
fn ac4_ac5_ac6_adversary_cannot_see_jj_git_or_orchestrator() {
    let fixture = build_fixture();
    ensure_isolation_dirs(&fixture.root);
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::AdversaryReview, "42", 0);

    let out = run_role_probe(WorkerRole::Adversary, &fixture.root, prepared.path());

    // AC-5/AC-6: the Adversary's namespace has NO *repository* `.jj/`, `.git/`,
    // or `.orchestrator/` — it literally cannot open them.
    assert!(
        out.contains("JJ=ABSENT"),
        "Adversary must NOT see the repository .jj/:\n{out}"
    );
    assert!(
        out.contains("GIT=ABSENT"),
        "Adversary must NOT see .git/:\n{out}"
    );
    assert!(
        out.contains("ORCH=ABSENT"),
        "Adversary must NOT see .orchestrator/:\n{out}"
    );
    // AC-4: it CAN see the workspace (RW) and `.crosslink/` (RO).
    assert!(out.contains("WS=PRESENT"), "must see workspace:\n{out}");
    assert!(out.contains("WS_RW"), "workspace must be writable:\n{out}");
    assert!(
        out.contains("CROSS=PRESENT"),
        "must see .crosslink/:\n{out}"
    );
    assert!(
        out.contains("CROSS_RO"),
        ".crosslink/ must be read-only:\n{out}"
    );
    // And with no repository `.jj/` mount, the JJ writability line never printed.
    assert!(
        !out.contains("JJ_RW"),
        "Adversary must not write the repository .jj/:\n{out}"
    );
    // HONEST CURRENT BEHAVIOR (finding #3): the workspace bind carries the jj
    // *workspace's* own working-copy `.jj`, so `<workspace>/.jj` IS present even
    // for the Adversary. It lacks only the *repository* `<root>/.jj` (asserted
    // ABSENT above). The plain-files Adversary workspace that would remove even
    // this is a documented follow-up, not built here.
    assert!(
        out.contains("WSJJ=PRESENT"),
        "the jj workspace's own <workspace>/.jj is present (finding #3):\n{out}"
    );
}

#[test]
fn ac4_implementer_sees_jj_and_colocated_git_rw_but_not_orchestrator() {
    let fixture = build_fixture();
    ensure_isolation_dirs(&fixture.root);
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::Implementing, "42", 0);

    let out = run_role_probe(WorkerRole::Implementer, &fixture.root, prepared.path());

    // The Implementer DOES see `.jj/`, read-write (it commits via `jj`).
    assert!(
        out.contains("JJ=PRESENT"),
        "Implementer must see .jj/:\n{out}"
    );
    assert!(out.contains("JJ_RW"), ".jj/ must be writable:\n{out}");
    // AND the colocated `.git/` backend, also present (finding #1): without it
    // jj cannot open the repo. REQ-6's `.orchestrator/` stays hidden.
    assert!(
        out.contains("GIT=PRESENT"),
        "Implementer must see the colocated .git/ (finding #1):\n{out}"
    );
    assert!(
        out.contains("ORCH=ABSENT"),
        "Implementer must NOT see .orchestrator/:\n{out}"
    );
    // Workspace RW + `.crosslink/` RO, same as every role.
    assert!(out.contains("WS_RW"), "workspace must be writable:\n{out}");
    assert!(out.contains("CROSS_RO"), ".crosslink/ must be RO:\n{out}");
}

/// The load-bearing proof of finding #1: with `.jj/` **and** the colocated
/// `.git/` both bound, jj is actually FUNCTIONAL inside the Implementer's
/// namespace — `jj status` and `jj log` succeed. Before the amendment (`.git/`
/// withheld) jj would die following `.jj/repo/store` to the unmounted `.git`,
/// so the Implementer sandbox was non-functional. Derives its bwrap argv from
/// the production `bwrap_prefix`, so it also guards against `base_mounts`/matrix
/// drift (finding #4).
#[test]
fn implementer_namespace_can_actually_run_jj() {
    let fixture = build_fixture();
    ensure_isolation_dirs(&fixture.root);
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::Implementing, "42", 0);

    // Run jj read commands inside the namespace. `jj` resolves via the inherited
    // PATH (nix profile), and the repo via cwd (base_mounts `--chdir` workspace).
    let script = r#"
if jj status >/tmp/jjout 2>&1; then echo JJ_STATUS_OK; else echo JJ_STATUS_FAILED; cat /tmp/jjout; fi
if jj log -r @ --no-graph >/dev/null 2>&1; then echo JJ_LOG_OK; else echo JJ_LOG_FAILED; fi
echo DONE
"#;
    let args = probe_argv(
        WorkerRole::Implementer,
        &fixture.root,
        prepared.path(),
        script,
    );
    let out = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("failed to invoke bwrap `{}`: {e}", args[0]));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("JJ_STATUS_OK"),
        "jj status must SUCCEED inside the Implementer namespace — this is the \
         colocated-.git fix (finding #1). status={}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status,
    );
    assert!(
        stdout.contains("JJ_LOG_OK"),
        "jj log must succeed inside the Implementer namespace:\n{stdout}"
    );
}

/// The Adversary's namespace, by contrast, canNOT reach the repository: with no
/// `.jj/` and no `.git/` bound, jj fails to find a repo. This is the negative
/// half of finding #1 — isolation of the non-committing role is intact.
#[test]
fn adversary_namespace_cannot_reach_the_repository() {
    let fixture = build_fixture();
    ensure_isolation_dirs(&fixture.root);
    let (_manager, prepared) = prepare_workspace(&fixture, Phase::AdversaryReview, "42", 0);

    // Probe the repository dirs directly (a plain jj invocation would still find
    // the workspace's own inert `.jj`; what must be gone is the repo backend).
    let out = run_role_probe(WorkerRole::Adversary, &fixture.root, prepared.path());
    assert!(out.contains("JJ=ABSENT"), "no repository .jj/:\n{out}");
    assert!(out.contains("GIT=ABSENT"), "no repository .git/:\n{out}");
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
