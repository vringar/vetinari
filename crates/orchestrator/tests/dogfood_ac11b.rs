//! AC-11b — the self-dogfood milestone: drive one crosslink issue from
//! `phase:graphed` to `phase:merged`, HEADLESS, on a **shell.nix-bearing,
//! real-cargo** target (the shape a live `claude` Implementer builds against),
//! generalizing the AC-11a `hello` fixture dogfood.
//!
//! Two tests share one target ([`build_target_fixture`]):
//!
//! - [`ac11b_direct_dogfood_lands_on_shell_nix_target`] — DETERMINISTIC, always
//!   runs. It proves the orchestration end-to-end (graphed → implementing →
//!   qa-gate → landing → merged) on the real-structure target using the Direct
//!   fake worker, so CI has a reliable AC-11b proof independent of any live
//!   agent. The target carries a real `shell.nix` + `npins/` (inert on the
//!   Direct path) so it is byte-for-byte the same repo the live path drives.
//!
//! - [`ac11b_live_claude_lands_say_hi`] — the REAL self-hosting run: a live
//!   `claude` Implementer, spawned by the orchestrator inside its bwrap +
//!   nix-shell sandbox, implements `say_hi`, runs `cargo test`, commits via `jj
//!   describe`, and the orchestrator QA-gates + fast-forward-lands it onto the
//!   target's `main`. It is `#[ignore]`d and additionally gated behind
//!   `VETINARI_LIVE_CLAUDE=1` (a live agent is slow + nondeterministic + spends
//!   real API budget), and it must run from inside the dev shell (bwrap +
//!   nix-shell + claude on PATH). The pipeline up to the Anthropic API boundary
//!   is already proven deterministically by the test above and the nested-bwrap
//!   isolation tests; this test closes the loop through the live agent.
//!
//! Everything orchestrator-side runs through library calls (AC-24); the only
//! shell-outs are test-support (`build_target_fixture` drives `jj`/`crosslink`
//! to provision the repo, and the assertions read the jj log).

mod common;

use std::path::Path;
use std::process::Command;

use common::{build_target_fixture, fake_adversary_clean, fake_implementer, unique_session};
use orchestrator::config::{OrchestratorConfig, WorkerConfig, WorkerKind};
use orchestrator::events::{read_all, EventLog, ORCHESTRATOR_DIR};
use orchestrator::pump::{BuildPump, IssueOutcome};
use orchestrator::spawn::{SandboxPin, Spawner};
use orchestrator::state::{EventKind, Phase, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_crosslink_api::CrosslinkRepo;

/// The commit `main` points at in the repo at `cwd` (test-support read).
fn main_commit(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["log", "-r", "main", "--no-graph", "-T", "commit_id"])
        .current_dir(cwd)
        .output()
        .expect("jj log for main");
    assert!(out.status.success(), "jj log must succeed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The `say_hi` presence in the crate as `main` sees it (test-support read).
fn main_has_say_hi(cwd: &Path) -> bool {
    let out = Command::new("jj")
        .args(["file", "show", "-r", "main", "src/lib.rs"])
        .current_dir(cwd)
        .output()
        .expect("jj file show main:src/lib.rs");
    assert!(out.status.success(), "jj file show must succeed");
    String::from_utf8_lossy(&out.stdout).contains("fn say_hi")
}

/// Re-open a fresh crosslink handle (the pump consumed the original).
fn crosslink_reopen(root: &Path) -> CrosslinkRepo {
    CrosslinkRepo::open(root).expect("reopen crosslink repo")
}

/// Whether `needles` appears as an ordered (not necessarily contiguous)
/// subsequence of `haystack`.
fn contains_subsequence(haystack: &[(String, String)], needles: &[(&str, &str)]) -> bool {
    let mut it = haystack.iter();
    needles
        .iter()
        .all(|(nf, nt)| it.any(|(hf, ht)| hf == nf && ht == nt))
}

/// Assert the full happy-path landing: state `Merged`, `main` advanced to carry
/// `say_hi`, crosslink mirrors `phase:merged`, and `events.jsonl` recorded the
/// transitions + a QA pass. Shared by both AC-11b variants — the whole point is
/// that the Direct and the live claude worker converge on the *same* observable
/// end state.
fn assert_landed(root: &Path, issue_id: i64, main_before: &str) {
    let orchestrator_dir = root.join(ORCHESTRATOR_DIR);

    // state.db reads phase:merged (re-opened to prove durability).
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let issue = state
        .get_issue(&issue_id.to_string())
        .expect("read issue")
        .expect("issue row exists");
    assert_eq!(
        issue.phase,
        Phase::Merged,
        "state.db must read phase:merged"
    );
    assert_eq!(issue.phase_substate, None, "merged clears the substate");

    // main fast-forwarded to the worker's say_hi change.
    let main_after = main_commit(root);
    assert_ne!(&main_after, main_before, "main must have advanced");
    assert!(
        main_has_say_hi(root),
        "the target crate must now carry say_hi on main"
    );

    // crosslink mirrors the terminal phase (presentation, REQ-2).
    let info = crosslink_reopen(root)
        .read_issue(issue_id)
        .expect("read issue");
    assert!(
        info.labels.iter().any(|l| l == "phase:merged"),
        "crosslink must mirror phase:merged, got {:?}",
        info.labels
    );
    assert!(
        !info.labels.iter().any(|l| l == "phase:graphed"),
        "the stale phase:graphed label must be removed, got {:?}",
        info.labels
    );

    // events.jsonl recorded the transitions + the QA pass.
    let events = read_all(orchestrator_dir.join("events.jsonl")).expect("read events");
    let transitions: Vec<(String, String)> = events
        .iter()
        .filter(|e| e.kind == EventKind::Transition)
        .filter_map(|e| {
            let from = e.payload.get("from_phase")?.as_str()?.to_owned();
            let to = e.payload.get("to_phase")?.as_str()?.to_owned();
            Some((from, to))
        })
        .collect();
    assert!(
        contains_subsequence(
            &transitions,
            &[
                ("graphed", "implementing"),
                ("implementing", "qa-gate"),
                ("landing", "merged"),
            ],
        ),
        "events.jsonl must record graphed→implementing→qa-gate→…→landing→merged, got {transitions:?}"
    );
    assert!(
        events.iter().any(|e| e.kind == EventKind::QaResult
            && e.payload.get("result").and_then(|v| v.as_str()) == Some("pass")),
        "events.jsonl must record the QA pass"
    );
}

/// AC-11b (deterministic): the full graphed → merged loop on a shell.nix-bearing
/// real-cargo target, using the Direct fake worker. This is the CI-safe AC-11b
/// proof — no live claude, no sandbox, no API.
#[test]
fn ac11b_direct_dogfood_lands_on_shell_nix_target() {
    // The target's committed config selects the Direct worker. The argv itself
    // is supplied in-code with the committed fake-implementer's ABSOLUTE path,
    // because a committed config.toml cannot carry the tempdir-absolute path
    // (mirrors the AC-11a dogfood; the pump's relative-path resolution is for a
    // fixture script co-located under the target root, which the fake worker is
    // not).
    let fx = build_target_fixture("[worker]\nkind = \"direct\"\n");

    // Preconditions: shell.nix + npins are really present (the live-path shape),
    // and main does not yet carry the change.
    //
    // HONESTY (shell.nix is INERT on the Direct path): this deterministic test
    // uses the Direct fake worker, which runs its argv straight in the workspace
    // and NEVER invokes `nix-shell`. So the `shell.nix` + `npins/` here are only
    // asserted to be *present* (byte-for-byte the repo the live path drives) —
    // they are not entered. The `nix-shell <shell.nix>` dev-shell ENTRY is
    // exercised only by `ac11b_live_claude_lands_say_hi`. As a cheap, offline
    // guard that the shipped shell.nix is at least well-formed (so the live
    // target isn't silently broken), we `nix-instantiate --parse` it when nix is
    // available; a full evaluation/entry stays live-only.
    assert!(
        fx.root.join("shell.nix").is_file(),
        "target must have shell.nix"
    );
    assert!(fx.root.join("npins").is_dir(), "target must have npins/");
    assert_shell_nix_parses(&fx.root.join("shell.nix"));
    let main_before = main_commit(&fx.root);
    assert!(
        !main_has_say_hi(&fx.root),
        "precondition: main must not yet contain say_hi"
    );

    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");

    let (session, _guard) = unique_session("ac11b-direct");
    // The Direct worker path skips the pin guard, so the pin value is unused.
    let spawner = Spawner::new(session, &fx.root, SandboxPin::new("unused-direct"));

    let config = OrchestratorConfig {
        worker: WorkerConfig {
            kind: WorkerKind::Direct,
            argv: vec![
                "bash".to_owned(),
                fake_implementer().to_string_lossy().into_owned(),
            ],
            // A2: a Direct clean fake-adversary so the review round converges on
            // the first pass → lands → merged (the end state is unchanged).
            adversary_kind: WorkerKind::Direct,
            adversary_argv: vec![
                "bash".to_owned(),
                fake_adversary_clean().to_string_lossy().into_owned(),
            ],
            ..WorkerConfig::default()
        },
        worker_timeout_secs: 60,
        // Pin to a single clean round so the deterministic target lands on the
        // first adversary pass (the end state is unchanged).
        convergence: orchestrator::config::ConvergenceConfig {
            n_rounds: 1,
            ..Default::default()
        },
        ..OrchestratorConfig::default()
    };

    let pump = BuildPump::new(config, state, log, manager, spawner, crosslink);
    let outcomes = pump.run_until_idle().expect("pump must run to idle");

    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "the single seed issue must land in one pass, got {outcomes:?}"
    );
    assert_landed(&fx.root, fx.issue_id, &main_before);
}

/// AC-11b (LIVE self-hosting): a real `claude` Implementer, spawned by the
/// orchestrator inside its bwrap + nix-shell sandbox, drives the same issue to
/// `merged`. `#[ignore]`d and gated behind `VETINARI_LIVE_CLAUDE=1` — a live
/// agent is slow, nondeterministic, and spends real API budget, so it is never
/// part of the default `cargo test` run. Run it explicitly, from inside the dev
/// shell, with:
///
/// ```text
/// VETINARI_LIVE_CLAUDE=1 cargo test -p orchestrator --test dogfood_ac11b \
///     ac11b_live_claude_lands_say_hi -- --ignored --nocapture
/// ```
#[test]
#[ignore = "live claude worker: slow, nondeterministic, spends API budget — run with VETINARI_LIVE_CLAUDE=1 from the dev shell"]
fn ac11b_live_claude_lands_say_hi() {
    if std::env::var("VETINARI_LIVE_CLAUDE").as_deref() != Ok("1") {
        eprintln!("skipping live claude AC-11b: set VETINARI_LIVE_CLAUDE=1 to run");
        return;
    }

    // The bwrap store-path pin (REQ-4a) and the nix-shell launcher pin. In an
    // impure dev shell the shellHook exports these; if absent, derive them from
    // PATH so the live run is self-contained. The nix-shell pin KEEPS the
    // `nix-shell` basename (a plain readlink -f would collapse the symlink to
    // `nix`, changing argv[0]).
    ensure_sandbox_pins();

    // The target with the live-claude worker config (generous turn cap +
    // worker/QA timeouts — a live agent takes minutes). Loaded through the real
    // config path (OrchestratorConfig::load), exactly as `main.rs` does.
    let fx = build_target_fixture(
        "worker_timeout_secs = 1200\nqa_timeout_secs = 600\n\n[convergence]\nn_rounds = 1\n\n[worker]\nkind = \"claude\"\nmax_turns_implementer = 200\nadversary_kind = \"claude\"\nmax_turns_adversary = 100\n",
    );
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let config = OrchestratorConfig::load(&orchestrator_dir).expect("load target config");
    assert_eq!(
        config.worker.kind,
        WorkerKind::Claude,
        "target selects claude"
    );

    let main_before = main_commit(&fx.root);
    assert!(
        !main_has_say_hi(&fx.root),
        "precondition: no say_hi on main"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");

    let (session, _guard) = unique_session("ac11b-live");
    // Real spawn path: the pin guard runs. Build the spawner from the env pin.
    let spawner = Spawner::from_env(session, &fx.root).expect("spawner from env pin");

    let pump = BuildPump::new(config, state, log, manager, spawner, crosslink);
    // `run_until_idle` surfaces any OrchestratorError here (the `expect`), so a
    // clean return already proves no orchestrator-level failure.
    let outcomes = pump.run_until_idle().expect("pump must run to idle");
    eprintln!("live claude AC-11b outcomes: {outcomes:?}");

    // A LIVE claude run is nondeterministic: it may legitimately produce
    // `[Requeued, Merged]` (a QA fail then a recovering retry) rather than a
    // single `Merged`. Asserting an exact `[(id, Merged)]` vector is a
    // false-negative on the very path this test exercises. Instead assert the
    // DURABLE terminal state via `assert_landed` (phase:merged, main advanced,
    // QA pass recorded) and that the issue's LAST recorded outcome is `Merged`
    // — the terminal outcome, not an exact accumulation across ticks.
    let terminal = outcomes
        .iter()
        .rfind(|(id, _)| *id == fx.issue_id)
        .map(|(_, outcome)| *outcome);
    assert_eq!(
        terminal,
        Some(IssueOutcome::Merged),
        "the live claude worker's terminal outcome for the issue must be Merged, got {outcomes:?}"
    );
    assert_landed(&fx.root, fx.issue_id, &main_before);
}

/// Cheap, offline honesty guard for the deterministic test: confirm the target's
/// `shell.nix` at least *parses*, so the file the live path enters isn't silently
/// malformed. `nix-instantiate --parse` is a pure syntax parse — no evaluation,
/// no `import ./npins`, no network. If `nix-instantiate` isn't on PATH (a CI box
/// without nix) the check is skipped: the Direct path never enters the shell, so
/// this stays a best-effort guard, not a hard nix dependency of the CI test.
fn assert_shell_nix_parses(shell_nix: &Path) {
    let path_env = std::env::var("PATH").unwrap_or_default();
    let on_path = std::env::split_paths(&path_env)
        .map(|d| d.join("nix-instantiate"))
        .any(|p| p.exists());
    if !on_path {
        eprintln!("skipping shell.nix parse check: nix-instantiate not on PATH");
        return;
    }
    let out = Command::new("nix-instantiate")
        .args(["--parse".as_ref(), shell_nix.as_os_str()])
        .output()
        .expect("run nix-instantiate --parse");
    assert!(
        out.status.success(),
        "target shell.nix must at least parse:\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Ensure `VDD_BWRAP_PIN` + `VDD_NIX_SHELL_PIN` are set for the live spawn path,
/// deriving them from PATH when the dev-shell hook has not already exported
/// them.
fn ensure_sandbox_pins() {
    // `set_var` is safe on edition 2021; this runs in single-threaded test
    // setup before any worker spawn, so there is no data-race concern.
    if std::env::var("VDD_BWRAP_PIN")
        .ok()
        .filter(|v| !v.is_empty())
        .is_none()
    {
        if let Some(bwrap) = which_real("bwrap") {
            std::env::set_var("VDD_BWRAP_PIN", bwrap);
        }
    }
    if std::env::var("VDD_NIX_SHELL_PIN")
        .ok()
        .filter(|v| !v.is_empty())
        .is_none()
    {
        if let Some(ns) = which_real("nix-shell") {
            // Keep the `nix-shell` basename: readlink -f collapses the
            // nix-shell→nix symlink, which would flip argv[0] to `nix`. Only set
            // the pin if the reconstructed path actually exists — a pin at a
            // non-existent path would make the spawn fall back or fail opaquely.
            if let Some(dir) = Path::new(&ns).parent() {
                let pin = dir.join("nix-shell");
                if pin.exists() {
                    std::env::set_var("VDD_NIX_SHELL_PIN", pin.to_string_lossy().into_owned());
                }
            }
        }
    }
}

/// Resolve `program` on PATH and canonicalize it to its real store path.
fn which_real(program: &str) -> Option<String> {
    let path_env = std::env::var("PATH").unwrap_or_default();
    std::env::split_paths(&path_env)
        .map(|d| d.join(program))
        .find(|p| p.exists())
        .and_then(|p| std::fs::canonicalize(p).ok())
        .map(|p| p.to_string_lossy().into_owned())
}
