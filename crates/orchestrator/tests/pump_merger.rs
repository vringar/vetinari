//! L4 (#18, REQ-19) — the Merger role wired into the landing-conflict path.
//!
//! These headless, Direct-fake-worker tests drive the build pump's landing step
//! over a **pre-staged rebase conflict** and prove the load-bearing behaviours:
//!
//! - **Merger resolves → lands:** a change whose rebase onto `main` conflicts is
//!   NOT parked immediately — a Merger worker resolves the conflict, post-merge
//!   QA passes, and the pump retries the fast-forward ONCE → `phase:merged`, with
//!   `main` advanced to a conflict-free tree carrying BOTH sides' content.
//! - **Merger fails → parks:** a Merger that leaves the conflict unresolved (a
//!   valid DONE but the tree still conflicts) parks the issue at
//!   `phase:awaiting-human-merge` with a `--kind blocker`, and `main` is left
//!   exactly where it was (never rewound, never advanced to a conflicted tree).
//!
//! The conflict is staged the same way `landing.rs`'s conflict test stages it:
//! the worker commits its change, then `main` advances with a CONFLICTING edit to
//! the same file, so rebasing the worker's change onto the new `main` cannot
//! apply cleanly. The pump's landing then dispatches the Merger. All Direct fake
//! workers, no live claude — mirrors `pump_adversary_loop.rs`.

mod common;

use std::path::Path;
use std::process::Command;

use common::{build_fixture, fake_implementer, fake_merger, fake_merger_unresolved, Fixture};
use orchestrator::config::{OrchestratorConfig, WorkerConfig};
use orchestrator::events::{EventLog, ORCHESTRATOR_DIR};
use orchestrator::pump::{BuildPump, IssueOutcome};
use orchestrator::spawn::{SandboxPin, Spawner};
use orchestrator::state::{IssueRow, Phase, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_crosslink_api::CrosslinkRepo;
use vetinari_zellij_host::{session_ensure, SessionHandle};

/// Serializes zellij-touching tests: the `zellij` CLI shares one background
/// server + socket, and cargo runs integration tests multithreaded.
static ZELLIJ_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

/// Run `program args...` in `cwd`, panicking with captured output on failure.
fn run(program: &str, args: &[&str], cwd: &Path) {
    let out = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn `{program}`: {e}"));
    assert!(
        out.status.success(),
        "`{program} {}` failed in {}:\n{}",
        args.join(" "),
        cwd.display(),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// The change id of `@` in the repo rooted at `cwd` (test-support read).
fn wc_change_id(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["log", "-r", "@", "--no-graph", "-T", "change_id"])
        .current_dir(cwd)
        .output()
        .expect("jj log for change id");
    assert!(out.status.success(), "jj log must succeed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The commit `main` points at (test-support read).
fn main_commit(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["log", "-r", "main", "--no-graph", "-T", "commit_id"])
        .current_dir(cwd)
        .output()
        .expect("jj log for main");
    assert!(out.status.success(), "jj log must succeed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `src/lib.rs` at `main`, via `jj file show` (test-support read).
fn main_lib_rs(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["file", "show", "-r", "main", "src/lib.rs"])
        .current_dir(cwd)
        .output()
        .expect("jj file show main:src/lib.rs");
    assert!(out.status.success(), "jj file show must succeed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A config dispatching the given Direct merger script, tight CI timeouts.
fn config_for(merger: &Path) -> OrchestratorConfig {
    OrchestratorConfig {
        worker: WorkerConfig {
            merger_argv: vec!["bash".to_owned(), merger.to_string_lossy().into_owned()],
            ..WorkerConfig::default()
        },
        worker_timeout_secs: 60,
        ..OrchestratorConfig::default()
    }
}

/// Build a pump over a fresh fixture with the given fake merger. Returns the
/// fixture, the pump, and the session guard (hold all three for the test).
fn pump_over(tag: &str, merger: &Path) -> (Fixture, BuildPump, SessionGuard) {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");
    let (session, guard) = unique_session(tag);
    let spawner = Spawner::new(session, &fx.root, SandboxPin::new("unused-direct"));
    let pump = BuildPump::new(config_for(merger), state, log, manager, spawner, crosslink);
    (fx, pump, guard)
}

/// Stage the rebase conflict: run the fake Implementer (commits `say_hi` on `@`),
/// then advance `main` with a CONFLICTING trailing edit to the same file. Seeds
/// the issue at `phase:converged` so `land_change` starts the landing machine.
/// Returns the Implementer's change id (the landing target).
fn stage_conflict(fx: &Fixture) -> String {
    let orch = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orch.join("state.db")).expect("open state.db");
    state
        .upsert_issue(&IssueRow::new(fx.issue_id.to_string(), Phase::Converged))
        .expect("seed converged issue");

    // The worker commits its say_hi change on `@` (a child of main).
    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);

    // Advance `main` with a CONFLICTING edit to the SAME file: a new change off
    // main appending different trailing content, then move the main bookmark to
    // it. Rebasing the worker's change onto the new main now conflicts.
    run(
        "jj",
        &["new", "main", "-m", "conflicting main edit"],
        &fx.root,
    );
    let lib = fx.root.join("src/lib.rs");
    let mut src = std::fs::read_to_string(&lib).expect("read lib.rs");
    src.push_str("\n// conflicting trailing edit on main\npub const MAIN_MARK: u8 = 1;\n");
    std::fs::write(&lib, src).expect("write conflicting main edit");
    run("jj", &["bookmark", "set", "main", "-r", "@"], &fx.root);

    change
}

/// Merger resolves → lands. The rebase conflicts, the Merger resolves it,
/// post-merge QA passes, and the pump retries the fast-forward ONCE → Merged.
/// `main` advances to a conflict-free tree carrying both `say_hi` and `MAIN_MARK`.
#[test]
fn merger_resolves_conflict_and_lands_merged() {
    let (fx, pump, _guard) = pump_over("merger-ok", &fake_merger());
    let change = stage_conflict(&fx);
    let main_before = main_commit(&fx.root);

    let outcome = pump
        .land_change(fx.issue_id, &change)
        .expect("landing with a Merger must not error");
    assert_eq!(
        outcome,
        IssueOutcome::Merged,
        "a Merger-resolved conflict must land → Merged, got {outcome:?}"
    );

    // main advanced (fast-forwarded past the merge) to a conflict-free tree that
    // preserves BOTH the worker's say_hi and main's MAIN_MARK.
    let main_after = main_commit(&fx.root);
    assert_ne!(
        main_after, main_before,
        "main must advance to the merged change"
    );
    let lib = main_lib_rs(&fx.root);
    assert!(
        lib.contains("fn say_hi"),
        "merge must keep the worker's say_hi:\n{lib}"
    );
    assert!(
        lib.contains("MAIN_MARK"),
        "merge must keep main's MAIN_MARK:\n{lib}"
    );
    assert!(
        !lib.contains("<<<<<<<") && !lib.contains(">>>>>>>"),
        "the landed tree must be conflict-free:\n{lib}"
    );

    // state.db authority: Merged, and the Merger was accounted for.
    let state = StateDb::open(fx.root.join(ORCHESTRATOR_DIR).join("state.db")).expect("reopen");
    let issue = state
        .get_issue(&fx.issue_id.to_string())
        .expect("read")
        .expect("row");
    assert_eq!(issue.phase, Phase::Merged, "must reach merged");
    assert_eq!(
        issue.landing_retry_count, 1,
        "exactly one Merger spawn must be recorded, got {}",
        issue.landing_retry_count
    );
    // No worker rows leaked, no workspace lingers.
    assert!(
        state.list_active_workers().expect("workers").is_empty(),
        "no active_workers row may leak after a Merger land"
    );
}

/// Merger fails → parks. A Merger that leaves the conflict unresolved parks the
/// issue at `phase:awaiting-human-merge` with a `--kind blocker`, and `main` is
/// left exactly where it was — never advanced to a conflicted tree, never
/// rewound.
#[test]
fn unresolved_merger_parks_for_human_and_leaves_main() {
    let (fx, pump, _guard) = pump_over("merger-fail", &fake_merger_unresolved());
    let change = stage_conflict(&fx);
    let main_before = main_commit(&fx.root);

    let outcome = pump
        .land_change(fx.issue_id, &change)
        .expect("an unresolved conflict is a handled outcome, not a hard error");
    assert_eq!(
        outcome,
        IssueOutcome::AwaitingHumanMerge,
        "an unresolved Merger must park for a human, got {outcome:?}"
    );

    // main is UNCHANGED — never advanced to a conflicted tree, never rewound.
    assert_eq!(
        main_commit(&fx.root),
        main_before,
        "a failed Merger must leave main exactly where it was"
    );

    let state = StateDb::open(fx.root.join(ORCHESTRATOR_DIR).join("state.db")).expect("reopen");
    let issue = state
        .get_issue(&fx.issue_id.to_string())
        .expect("read")
        .expect("row");
    assert_eq!(
        issue.phase,
        Phase::AwaitingHumanMerge,
        "an unresolved Merger parks at awaiting-human-merge"
    );
    assert!(
        state.list_active_workers().expect("workers").is_empty(),
        "no active_workers row may leak after a parked Merger"
    );

    // A `--kind blocker` recording the conflict context was posted (AC-14).
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let blockers = crosslink
        .list_comments(fx.issue_id)
        .expect("list comments")
        .into_iter()
        .filter(|c| c.kind == "blocker")
        .count();
    assert!(
        blockers >= 1,
        "a parked landing must carry a --kind blocker with the conflict context (AC-14)"
    );

    // No workspace lingers.
    let ws_root = fx.root.join(".workspace");
    if ws_root.exists() {
        let lingering: Vec<_> = std::fs::read_dir(&ws_root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            lingering.is_empty(),
            "no workspace may linger after a parked Merger, found {lingering:?}"
        );
    }
}
