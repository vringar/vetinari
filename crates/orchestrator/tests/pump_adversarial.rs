//! Adversarial-review regressions for the #15 build pump:
//!
//! - **QA-retry re-drive (#1):** an issue whose QA always fails is re-driven
//!   from `state.db` each round (proving the retry loop is LIVE, not dead code)
//!   and poisons after `MAX_QA_RETRIES` — the bound is actually reached.
//! - **Empty-commit guard (#4):** a worker that writes a valid DONE but makes no
//!   change → landing is refused, `main` does not move, the issue is not Merged.
//! - **state.db-authority pickup (#1):** an issue sitting at `Implementing` in
//!   `state.db` with its `phase:graphed` label already removed is still selected
//!   by the drive step (routing reads `state.db`, never a label).
//!
//! All headless, Direct fake workers, no live claude. Mirrors `dogfood.rs`.

mod common;

use std::path::Path;
use std::process::Command;

use common::{
    build_fixture, fake_adversary_clean, fake_implementer, fake_implementer_empty,
    fake_implementer_qa_fail,
};
use orchestrator::config::{OrchestratorConfig, WorkerConfig};
use orchestrator::pump::{BuildPump, IssueOutcome, MAX_QA_RETRIES};
use orchestrator::spawn::{SandboxPin, Spawner};
use orchestrator::state::{IssueRow, Phase, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_crosslink_api::CrosslinkRepo;
use vetinari_zellij_host::{session_ensure, SessionHandle};

/// Serializes zellij-touching tests: the `zellij` CLI shares one background
/// server + socket, and cargo runs integration tests multithreaded. Mirrors
/// `dogfood.rs` / `spawn_dispatch.rs`.
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

fn main_commit(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["log", "-r", "main", "--no-graph", "-T", "commit_id"])
        .current_dir(cwd)
        .output()
        .expect("jj log for main");
    assert!(out.status.success(), "jj log must succeed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A config that dispatches `script` as the Direct implementer (absolute path
/// passes through `worker_argv` untouched), with tight timeouts for CI. The
/// Adversary is the Direct clean fake (A2: QA-pass now runs a review round
/// before landing, so a resolvable, converging Adversary keeps the happy-path
/// cases landing on their first clean round).
fn config_for(script: &Path) -> OrchestratorConfig {
    OrchestratorConfig {
        worker: WorkerConfig {
            argv: vec!["bash".to_owned(), script.to_string_lossy().into_owned()],
            adversary_argv: vec![
                "bash".to_owned(),
                fake_adversary_clean().to_string_lossy().into_owned(),
            ],
            ..WorkerConfig::default()
        },
        worker_timeout_secs: 60,
        ..OrchestratorConfig::default()
    }
}

/// #1 — QA-fail retry loop is LIVE and bounded. A worker that always fails QA
/// is re-driven from `state.db` each round; after `MAX_QA_RETRIES` attempts the
/// issue poisons (proving the loop ran the full bound — it was dead code before
/// the ingest/drive split).
#[test]
fn qa_failure_is_redriven_and_poisons_at_bound() {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(".orchestrator");

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = orchestrator::events::EventLog::open(&orchestrator_dir).expect("open events");
    let manager = WorkspaceManager::load(&fx.root).expect("load manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");

    let (session, _guard) = unique_session("qa-retry");
    let spawner = Spawner::new(session, &fx.root, SandboxPin::new("unused-direct"));

    let pump = BuildPump::new(
        config_for(&fake_implementer_qa_fail()),
        state,
        log,
        manager,
        spawner,
        crosslink,
    );

    let main_before = main_commit(&fx.root);
    let outcomes = pump.run_until_idle().expect("pump runs to idle");

    // The issue is re-driven each round (Requeued) until the bound, then poisons.
    let requeues = outcomes
        .iter()
        .filter(|(_, o)| matches!(o, IssueOutcome::Requeued))
        .count();
    let poisons = outcomes
        .iter()
        .filter(|(_, o)| matches!(o, IssueOutcome::OrchestratorError))
        .count();
    assert_eq!(
        requeues,
        (MAX_QA_RETRIES - 1) as usize,
        "QA-fail must re-drive MAX_QA_RETRIES-1 times before poisoning, got {outcomes:?}"
    );
    assert_eq!(
        poisons, 1,
        "the retry budget must be reached and the issue poisoned exactly once, got {outcomes:?}"
    );

    // Final state.db authority: orchestrator-error. main never moved.
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen");
    let issue = state
        .get_issue(&fx.issue_id.to_string())
        .expect("read")
        .expect("row");
    assert_eq!(issue.phase, Phase::OrchestratorError);
    assert_eq!(
        main_commit(&fx.root),
        main_before,
        "a QA-failing issue must never advance main"
    );
}

/// #4 — empty-commit guard. A worker that writes a valid DONE but makes no
/// change must not fast-forward `main`; the issue must not be Merged.
#[test]
fn empty_commit_is_refused_and_does_not_merge() {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(".orchestrator");

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = orchestrator::events::EventLog::open(&orchestrator_dir).expect("open events");
    let manager = WorkspaceManager::load(&fx.root).expect("load manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");

    let (session, _guard) = unique_session("empty-commit");
    let spawner = Spawner::new(session, &fx.root, SandboxPin::new("unused-direct"));

    let pump = BuildPump::new(
        config_for(&fake_implementer_empty()),
        state,
        log,
        manager,
        spawner,
        crosslink,
    );

    let main_before = main_commit(&fx.root);
    let outcomes = pump.run_until_idle().expect("pump runs to idle");

    // The empty change is refused → poison, never Merged.
    assert!(
        outcomes
            .iter()
            .all(|(_, o)| !matches!(o, IssueOutcome::Merged)),
        "an empty-change worker must never yield Merged, got {outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|(_, o)| matches!(o, IssueOutcome::OrchestratorError)),
        "an empty-change worker must be treated as a failure (poison), got {outcomes:?}"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen");
    let issue = state
        .get_issue(&fx.issue_id.to_string())
        .expect("read")
        .expect("row");
    assert_ne!(issue.phase, Phase::Merged, "issue must not be Merged");
    assert_eq!(
        main_commit(&fx.root),
        main_before,
        "main must NOT move for an empty commit (#4)"
    );
}

/// #1 — state.db authority pickup. An issue at `Implementing` in `state.db`
/// whose `phase:graphed` label has already been removed is still selected by
/// the drive step and driven to Merged. Proves routing reads `state.db`, not a
/// label.
#[test]
fn state_db_implementing_is_driven_without_graphed_label() {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(".orchestrator");

    // Pre-seed state.db: the issue is already at Implementing (as if a prior
    // tick requeued it), and strip its phase:graphed label so ingest cannot
    // re-discover it. If the pump still drives it, it can only be reading
    // state.db authority.
    {
        let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
        state
            .upsert_issue(&IssueRow::new(fx.issue_id.to_string(), Phase::Implementing))
            .expect("seed implementing row");
    }
    let cl = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    cl.label_remove(fx.issue_id, "phase:graphed")
        .expect("remove graphed label");
    assert!(
        cl.list_by_label("open", "phase:graphed")
            .expect("list")
            .is_empty(),
        "precondition: no issue carries phase:graphed anymore"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let log = orchestrator::events::EventLog::open(&orchestrator_dir).expect("open events");
    let manager = WorkspaceManager::load(&fx.root).expect("load manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");

    let (session, _guard) = unique_session("authority");
    let spawner = Spawner::new(session, &fx.root, SandboxPin::new("unused-direct"));

    let pump = BuildPump::new(
        config_for(&fake_implementer()),
        state,
        log,
        manager,
        spawner,
        crosslink,
    );

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "an Implementing issue in state.db (no graphed label) must still be driven to Merged, got {outcomes:?}"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen");
    assert_eq!(
        state
            .get_issue(&fx.issue_id.to_string())
            .expect("read")
            .expect("row")
            .phase,
        Phase::Merged,
    );
}
