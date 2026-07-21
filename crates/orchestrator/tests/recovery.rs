//! Fixture-backed crash-recovery tests (REQ-15, AC-17, AC-18).
//!
//! These drive [`orchestrator::recovery::recover`] against a *real* jj repository
//! — the `hello` dogfood fixture stood up by [`common::build_fixture`] — proving
//! the deterministic recovery table:
//!
//! - **Crash mid-implementing (no DONE):** an orphan workspace + an
//!   `active_workers` row with no `_orchestrator/DONE` ⇒ `recover` cleans the
//!   workspace, drops the worker row, and rolls the issue back to `implementing`
//!   so the pump can re-drive it (asserted by driving the pump to `merged`).
//! - **Crash mid-landing (AC-18):** a persisted `rebase_done_bookmark_pending`
//!   substate ⇒ `recover` completes the landing to `merged` via `resume_from`,
//!   and a second `recover` is a no-op.
//! - **Crash mid-translation (AC-17):** a finished worker (DONE present) whose
//!   comments are already in the `posted_artifacts` ledger ⇒ `recover`-driven
//!   re-translation posts each comment at most once.
//! - **Idempotency:** `recover` run twice yields the same final state.
//!
//! Every `.jj/` op runs through the [`WorkspaceManager`] gate (REQ-5a); no
//! `jj`/`git` subprocess is used from the orchestrator side (AC-24) — the only
//! shell-outs here are test-support (running the committed worker script and
//! reading the jj log).

mod common;

use std::path::Path;
use std::process::Command;

use common::{build_fixture, fake_adversary_clean, fake_implementer, Fixture};
use orchestrator::artifacts::{ArtifactSet, DoneSentinel};
use orchestrator::config::{OrchestratorConfig, WorkerConfig};
use orchestrator::events::{EventLog, ORCHESTRATOR_DIR};
use orchestrator::landing::LandingOutcome;
use orchestrator::pump::{BuildPump, IssueOutcome};
use orchestrator::recovery::{recover, RecoveryAction};
use orchestrator::spawn::{SandboxPin, Spawner};
use orchestrator::state::{
    ActiveWorkerRow, IssueRow, Phase, PhaseSubstate, PostedArtifact, StateDb, WorkerRole,
};
use orchestrator::workspace::{WorkspaceManager, WorkspaceName, WORKSPACE_DIR};
use vetinari_crosslink_api::CrosslinkRepo;
use vetinari_zellij_host::{session_ensure, SessionHandle};

/// Serializes zellij-touching tests, mirroring the dogfood harness.
static ZELLIJ_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Kills the test's zellij session on drop and releases the shared lock.
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

/// A unique headless zellij session holding the shared lock for its lifetime.
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

/// Open a fresh `state.db` + `events.jsonl` pair under the fixture's
/// `.orchestrator/`. Returns them plus the string issue id used throughout.
fn open_state(fx: &Fixture) -> (StateDb, EventLog, String) {
    let orch = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orch.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orch).expect("open events.jsonl");
    (state, log, fx.issue_id.to_string())
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

/// Count how many comments of `kind` the crosslink issue `id` carries, via the
/// `crosslink issue show --json` CLI (test-support shell-out; the AC-24 lint
/// scopes to `src/**`). Used to prove the at-most-once translation guarantee
/// (AC-17) end-to-end, past the ledger and into crosslink's own store.
fn count_comments_of_kind(cwd: &Path, id: i64, kind: &str) -> usize {
    let out = Command::new("crosslink")
        .args(["issue", "show", &id.to_string(), "--json"])
        .current_dir(cwd)
        .output()
        .expect("crosslink issue show --json");
    assert!(
        out.status.success(),
        "crosslink issue show failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("issue show emits JSON");
    json.get("comments")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|c| c.get("kind").and_then(|k| k.as_str()) == Some(kind))
                .count()
        })
        .unwrap_or(0)
}

/// The commit `main` points at in the repo at `cwd` (test-support read).
fn main_has_say_hi(cwd: &Path) -> bool {
    let out = Command::new("jj")
        .args(["file", "show", "-r", "main", "src/lib.rs"])
        .current_dir(cwd)
        .output()
        .expect("jj file show");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).contains("fn say_hi")
}

/// AC-11a-style pump wiring against the fixture, for the "re-drive after recovery"
/// assertion. Returns the pump plus the session guard the caller must hold for
/// the pump's lifetime (dropping it kills the zellij session).
fn build_pump(
    fx: &Fixture,
    state: StateDb,
    log: EventLog,
    manager: WorkspaceManager,
) -> (BuildPump, SessionGuard) {
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let (session, guard) = unique_session("recovery");
    let spawner = Spawner::new(session, &fx.root, SandboxPin::new("unused-direct"));
    let config = OrchestratorConfig {
        worker: WorkerConfig {
            argv: vec![
                "bash".to_owned(),
                fake_implementer().to_string_lossy().into_owned(),
            ],
            // A2: QA-pass now runs an adversary review before landing. Use the
            // Direct clean fake-adversary so a recovered issue still drives all
            // the way to `merged` on its first clean review round.
            adversary_argv: vec![
                "bash".to_owned(),
                fake_adversary_clean().to_string_lossy().into_owned(),
            ],
            ..WorkerConfig::default()
        },
        worker_timeout_secs: 60,
        ..OrchestratorConfig::default()
    };
    (
        BuildPump::new(config, state, log, manager, spawner, crosslink),
        guard,
    )
}

/// Crash mid-implementing with **no DONE**: an orphan workspace and an
/// `active_workers` row, no sentinel. `recover` must clean the workspace, drop
/// the worker row, roll the issue back to `implementing`, and leave the repo so
/// the pump drives it all the way to `merged`.
#[test]
fn recover_cleans_crashed_implementer_then_pump_reaches_merged() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = open_state(&fx);

    // Seed the issue mid-work at `implementing`.
    state
        .upsert_issue(&IssueRow::new(&issue_id, Phase::Implementing))
        .expect("seed implementing issue");

    // Materialize a real orphan workspace (as a crashed worker would leave) and
    // register the active_workers row pointing at it — but write NO DONE.
    let name = WorkspaceName::generate(Phase::Implementing, &issue_id, 0);
    let prepared = manager
        .prepare(&name, "main")
        .expect("prepare orphan workspace");
    let ws_path = prepared.path().to_path_buf();
    assert!(ws_path.exists(), "orphan workspace dir exists pre-recovery");
    assert!(
        DoneSentinel::verify(&ws_path).is_err(),
        "precondition: no DONE in the orphan workspace"
    );

    let worker = ActiveWorkerRow {
        worker_uuid: "crashed-uuid-1".to_owned(),
        issue_id: issue_id.clone(),
        role: WorkerRole::Implementer,
        round: 0,
        workspace_path: ws_path.clone(),
        pid: None,
        spawned_at: 1,
        last_heartbeat: 1,
    };
    state
        .upsert_worker(&worker)
        .expect("register crashed worker row");

    // Recover.
    let actions = recover(&state, &log, &manager, None).expect("recover must succeed");
    assert_eq!(
        actions,
        vec![RecoveryAction::CleanedCrashedWorker {
            issue_id: issue_id.clone()
        }],
        "the crashed worker must be the only reconciliation, got {actions:?}"
    );

    // The workspace was forgotten + removed, the worker row dropped, and the
    // issue rolled back to a drivable `implementing`.
    assert!(
        !ws_path.exists(),
        "recover must rm -rf the orphan workspace"
    );
    assert!(
        manager
            .list()
            .expect("list workspaces")
            .iter()
            .all(|w| w != &name.as_str()),
        "recover must jj-forget the orphan workspace"
    );
    assert!(
        state
            .list_active_workers()
            .expect("list workers")
            .is_empty(),
        "recover must drop the crashed worker row"
    );
    let issue = state.get_issue(&issue_id).unwrap().unwrap();
    assert_eq!(issue.phase, Phase::Implementing);
    assert_eq!(issue.phase_substate, None);

    // Idempotent: a second recover finds nothing to do.
    let again = recover(&state, &log, &manager, None).expect("second recover");
    assert!(
        again.is_empty(),
        "second recover must be a no-op, got {again:?}"
    );

    // The pump can now re-drive the recovered issue to merged from a fresh
    // workspace (REQ-8 fresh context).
    let (pump, _session_guard) = build_pump(&fx, state, log, manager);
    let outcomes = pump.run_until_idle().expect("pump must run to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "the recovered issue must land in one pass, got {outcomes:?}"
    );
    assert!(
        main_has_say_hi(&fx.root),
        "main must carry say_hi after the pump re-drove the recovered issue"
    );
}

/// Crash mid-AdversaryReview (#1): the pump forgets the Implementer workspace
/// BEFORE entering review, so a crash during review leaves only the Adversary
/// worker (its workspace + row, no DONE) and NO orphan Implementer workspace.
/// `recover` must clean the Adversary workspace, drop the row, roll the issue
/// back to `implementing`, and leave `.workspace/` empty — then the pump
/// re-drives the recovered issue all the way to `merged`.
#[test]
fn recover_cleans_crashed_adversary_leaves_no_orphan_then_reaches_merged() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = open_state(&fx);

    // Seed the issue mid-review at `adversary-review`. Per the #1 invariant the
    // Implementer workspace was already forgotten before review, so it does NOT
    // exist here — only the Adversary's does.
    state
        .upsert_issue(&IssueRow::new(&issue_id, Phase::AdversaryReview))
        .expect("seed adversary-review issue");

    // Materialize the crashed Adversary's workspace + row, with NO DONE.
    let adv_name = WorkspaceName::generate(Phase::AdversaryReview, &issue_id, 0);
    let adv_prepared = manager
        .prepare(&adv_name, "main")
        .expect("prepare adversary workspace");
    let adv_path = adv_prepared.path().to_path_buf();
    assert!(adv_path.exists(), "adversary workspace exists pre-recovery");
    state
        .upsert_worker(&ActiveWorkerRow {
            worker_uuid: "crashed-adversary-1".to_owned(),
            issue_id: issue_id.clone(),
            role: WorkerRole::Adversary,
            round: 0,
            workspace_path: adv_path.clone(),
            pid: None,
            spawned_at: 1,
            last_heartbeat: 1,
        })
        .expect("register crashed adversary row");

    // Recover: cleans the adversary workspace + row, rolls back to implementing.
    let actions = recover(&state, &log, &manager, None).expect("recover must succeed");
    assert_eq!(
        actions,
        vec![RecoveryAction::CleanedCrashedWorker {
            issue_id: issue_id.clone()
        }],
        "the crashed adversary must be the only reconciliation, got {actions:?}"
    );
    assert!(
        !adv_path.exists(),
        "recover must rm -rf the adversary workspace"
    );
    assert!(
        state
            .list_active_workers()
            .expect("list workers")
            .is_empty(),
        "recover must drop the crashed adversary row"
    );
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::Implementing
    );

    // NO orphan Implementer (or any) workspace lingers under `.workspace/`.
    let ws_root = fx.root.join(WORKSPACE_DIR);
    if ws_root.exists() {
        let lingering: Vec<_> = std::fs::read_dir(&ws_root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            lingering.is_empty(),
            "no orphan workspace (esp. an Implementer one) may linger, found {lingering:?}"
        );
    }

    // Idempotent second pass, then the pump re-drives to merged.
    let again = recover(&state, &log, &manager, None).expect("second recover");
    assert!(
        again.is_empty(),
        "second recover must be a no-op, got {again:?}"
    );

    let (pump, _session_guard) = build_pump(&fx, state, log, manager);
    let outcomes = pump.run_until_idle().expect("pump must run to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "the recovered issue must land in one pass, got {outcomes:?}"
    );
    assert!(
        main_has_say_hi(&fx.root),
        "main must carry say_hi after re-drive"
    );
}

/// Crash mid-landing (AC-18): the rebase completed pre-crash and the substate is
/// persisted as `rebase_done_bookmark_pending`, but the bookmark move had not
/// happened. `recover` re-derives the change from the implement workspace and
/// completes the landing to `merged` via `resume_from`; a second `recover` is a
/// no-op.
#[test]
fn recover_resumes_landing_to_merged_and_is_idempotent() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = open_state(&fx);

    // Stand up the implement workspace the pump would have landed from, run the
    // worker inside it, and register nothing in active_workers (landing has no
    // worker row — the pump removes it before landing).
    let name = WorkspaceName::generate(Phase::Implementing, &issue_id, 0);
    let prepared = manager
        .prepare(&name, "main")
        .expect("prepare implement workspace");
    run(
        "bash",
        &[fake_implementer().to_str().unwrap()],
        prepared.path(),
    );

    // The change to land is the implement workspace's working-copy commit — the
    // same value recovery re-derives from the workspace entries.
    let working_copy = |manager: &WorkspaceManager| -> String {
        manager
            .entries()
            .expect("entries")
            .into_iter()
            .find(|e| e.name == name.as_str())
            .map(|e| e.working_copy_id)
            .expect("implement workspace has a working copy")
    };
    let change = working_copy(&manager);

    // Reconstruct the pre-crash state: rebase ran (worker change is a child of
    // main, so the rebase is a parent-wise no-op) and the substate was persisted
    // as `rebase_done_bookmark_pending`, but the bookmark move had not happened.
    manager
        .rebase(&change, "main")
        .expect("stage: rebase completed pre-crash");
    state
        .upsert_issue(&IssueRow::new(&issue_id, Phase::Landing))
        .expect("seed landing issue");
    state
        .set_phase(
            &issue_id,
            Phase::Landing,
            Some(PhaseSubstate::RebaseDoneBookmarkPending),
        )
        .expect("persist crashed-at substate");

    // The landing target is the workspace's CURRENT working-copy commit (the
    // rebase may have rewritten it); read it fresh, as recovery does.
    let landed_commit = working_copy(&manager);
    let main_before = manager.bookmark_target("main").expect("read main");
    assert_ne!(
        main_before.as_deref(),
        Some(landed_commit.as_str()),
        "precondition: the bookmark move had not happened before recovery"
    );

    // Recover: delegates to resume_from, completing the move to merged.
    let actions = recover(&state, &log, &manager, None).expect("recover must succeed");
    assert_eq!(
        actions,
        vec![RecoveryAction::ResumedLanding {
            issue_id: issue_id.clone(),
            outcome: LandingOutcome::Merged,
        }],
        "recovery must resume landing to merged, got {actions:?}"
    );

    let main_after = manager.bookmark_target("main").expect("read main after");
    assert_eq!(
        main_after.as_deref(),
        Some(landed_commit.as_str()),
        "recovery must complete the fast-forward to the landed change"
    );
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::Merged
    );

    // Idempotent: a second recover finds the issue terminal (merged) → no action.
    let again = recover(&state, &log, &manager, None).expect("second recover");
    assert!(
        again.is_empty(),
        "second recover must be a no-op, got {again:?}"
    );
    assert_eq!(
        manager.bookmark_target("main").expect("read main"),
        main_after,
        "the idempotent second recover must not move main"
    );
}

/// Crash mid-translation (AC-17): a finished worker (DONE present) whose comments
/// are already recorded in the `posted_artifacts` ledger. `recover`-driven
/// re-translation must post each comment **at most once** — the ledger suppresses
/// everything already posted, so the replay posts nothing.
#[test]
fn recover_replays_translation_at_most_once() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = open_state(&fx);

    // A finished worker: an implement workspace with a valid DONE.
    let name = WorkspaceName::generate(Phase::Implementing, &issue_id, 0);
    let prepared = manager
        .prepare(&name, "main")
        .expect("prepare implement workspace");
    run(
        "bash",
        &[fake_implementer().to_str().unwrap()],
        prepared.path(),
    );
    let ws_path = prepared.path().to_path_buf();
    let done = DoneSentinel::verify(&ws_path).expect("worker wrote a valid DONE");

    // Seed the issue at `implementing` (crashed BEFORE advancing to QA) with the
    // finished worker's row.
    let worker_uuid = "finished-uuid-1".to_owned();
    state
        .upsert_issue(&IssueRow::new(&issue_id, Phase::Implementing))
        .expect("seed implementing issue");
    state
        .upsert_worker(&ActiveWorkerRow {
            worker_uuid: worker_uuid.clone(),
            issue_id: issue_id.clone(),
            role: WorkerRole::Implementer,
            round: 0,
            workspace_path: ws_path.clone(),
            pid: None,
            spawned_at: 1,
            last_heartbeat: 1,
        })
        .expect("register finished worker row");

    // Pre-seed the ledger with EXACTLY the comments this worker's DONE would
    // translate to — modelling a crash AFTER the comments were posted but BEFORE
    // the orchestrator advanced (the AC-17 ledger-non-empty case).
    let set = ArtifactSet { done };
    let plan = orchestrator::artifacts::translation_plan(&worker_uuid, &set).expect("plan");
    assert!(
        !plan.is_empty(),
        "the implementer DONE yields at least one comment"
    );
    for item in &plan {
        let newly = state
            .record_posted(&PostedArtifact {
                issue_id: issue_id.clone(),
                artifact_path: item.artifact_path.clone(),
                content_sha: item.content_sha.clone(),
                finding_index: item.finding_index,
                worker_uuid: worker_uuid.clone(),
                comment_id: "pre-seeded".to_owned(),
                posted_at: 1,
            })
            .expect("seed ledger");
        assert!(newly, "each seeded ledger tuple is new");
    }

    // Recover WITH a crosslink handle so the replay path is exercised. Because the
    // ledger already holds every tuple, the replay must post NOTHING.
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let actions = recover(&state, &log, &manager, Some(&crosslink)).expect("recover");
    assert_eq!(
        actions,
        vec![RecoveryAction::ReplayedDone {
            issue_id: issue_id.clone(),
            posted: 0,
        }],
        "a ledger-covered replay must post zero comments, got {actions:?}"
    );

    // The issue rolled back to implementing and the worker row was dropped.
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::Implementing
    );
    assert!(state.list_active_workers().expect("workers").is_empty());

    // Idempotent: a second recover has no worker row / no DONE → no action.
    let again = recover(&state, &log, &manager, Some(&crosslink)).expect("second recover");
    assert!(
        again.is_empty(),
        "second recover must be a no-op, got {again:?}"
    );
}

/// Running `recover` twice over a fresh crash fixture converges to the same final
/// state — the top-level idempotency guarantee (REQ-15). Combines a crashed
/// implementer with a clean graphed issue and asserts the second pass is a no-op.
#[test]
fn recover_is_idempotent_over_mixed_state() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = open_state(&fx);

    // A crashed implementer (no DONE) plus a graphed issue that must be left
    // alone by recovery.
    state
        .upsert_issue(&IssueRow::new(&issue_id, Phase::Implementing))
        .expect("seed implementing");
    state
        .upsert_issue(&IssueRow::new("graphed-sibling", Phase::Graphed))
        .expect("seed graphed sibling");

    let name = WorkspaceName::generate(Phase::Implementing, &issue_id, 0);
    let prepared = manager.prepare(&name, "main").expect("prepare orphan");
    state
        .upsert_worker(&ActiveWorkerRow {
            worker_uuid: "u".to_owned(),
            issue_id: issue_id.clone(),
            role: WorkerRole::Implementer,
            round: 0,
            workspace_path: prepared.path().to_path_buf(),
            pid: None,
            spawned_at: 1,
            last_heartbeat: 1,
        })
        .expect("register worker");

    // First pass reconciles the crashed implementer only (the graphed sibling is
    // left for the pump).
    let first = recover(&state, &log, &manager, None).expect("first recover");
    assert_eq!(
        first,
        vec![RecoveryAction::CleanedCrashedWorker {
            issue_id: issue_id.clone()
        }],
    );

    // Snapshot the reconciled state.
    let implementing_after = state.get_issue(&issue_id).unwrap().unwrap();
    let graphed_after = state.get_issue("graphed-sibling").unwrap().unwrap();
    let workers_after = state.list_active_workers().unwrap();

    // Second pass is a no-op and leaves every row exactly as the first left it.
    let second = recover(&state, &log, &manager, None).expect("second recover");
    assert!(
        second.is_empty(),
        "second pass must be a no-op, got {second:?}"
    );
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap(),
        implementing_after
    );
    assert_eq!(
        state.get_issue("graphed-sibling").unwrap().unwrap(),
        graphed_after
    );
    assert_eq!(state.list_active_workers().unwrap(), workers_after);

    // Sanity: no orphan workspace directory lingers under `.workspace/`.
    let ws_root = fx.root.join(WORKSPACE_DIR);
    if ws_root.exists() {
        let lingering: Vec<_> = std::fs::read_dir(&ws_root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            lingering.is_empty(),
            "no orphan workspace must linger after recovery, found {lingering:?}"
        );
    }
}

/// The AC-17 at-most-once regression test — the one the old suite dodged.
///
/// A finished worker (DONE present) crashed BEFORE advancing, and the ledger is
/// **empty** (the crash happened before the comments were posted). `recover`
/// replays the translation (posting the `result` comment once, under the crashed
/// uuid), then rolls back to `implementing`; the pump then re-drives with a
/// FRESH uuid and re-translates the identical content.
///
/// With the old uuid-keyed ledger the fresh-uuid re-translation would post a
/// SECOND identical `result` comment — the AC-17 violation. With the
/// content-addressed, issue-scoped ledger the re-drive is a dedup no-op, so the
/// issue ends with EXACTLY ONE `result` comment. This test FAILS pre-fix, PASSES
/// post-fix.
#[test]
fn empty_ledger_replay_then_redrive_posts_result_comment_exactly_once() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = open_state(&fx);

    // A finished worker: an implement workspace with a valid DONE, crashed at
    // `implementing` before advancing to QA. The ledger is EMPTY.
    let name = WorkspaceName::generate(Phase::Implementing, &issue_id, 0);
    let prepared = manager
        .prepare(&name, "main")
        .expect("prepare implement workspace");
    run(
        "bash",
        &[fake_implementer().to_str().unwrap()],
        prepared.path(),
    );
    let ws_path = prepared.path().to_path_buf();
    DoneSentinel::verify(&ws_path).expect("worker wrote a valid DONE");

    state
        .upsert_issue(&IssueRow::new(&issue_id, Phase::Implementing))
        .expect("seed implementing issue");
    state
        .upsert_worker(&ActiveWorkerRow {
            worker_uuid: "crashed-uuid".to_owned(),
            issue_id: issue_id.clone(),
            role: WorkerRole::Implementer,
            round: 0,
            workspace_path: ws_path,
            pid: None,
            spawned_at: 1,
            last_heartbeat: 1,
        })
        .expect("register finished worker row");

    // Precondition: no result comment yet.
    assert_eq!(
        count_comments_of_kind(&fx.root, fx.issue_id, "result"),
        0,
        "no result comment before recovery"
    );

    // Recover WITH a crosslink handle: the empty ledger lets the replay post the
    // one result comment (under the crashed uuid), then rolls back to implementing.
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let actions = recover(&state, &log, &manager, Some(&crosslink)).expect("recover");
    assert_eq!(
        actions,
        vec![RecoveryAction::ReplayedDone {
            issue_id: issue_id.clone(),
            posted: 1,
        }],
        "empty-ledger replay posts the one result comment, got {actions:?}"
    );
    assert_eq!(
        count_comments_of_kind(&fx.root, fx.issue_id, "result"),
        1,
        "the replay posts exactly one result comment"
    );

    // Now let the pump re-drive the recovered issue with a FRESH uuid. Its
    // re-translation of the IDENTICAL result.md must be a ledger no-op (the key
    // is issue+content, not uuid), so no SECOND result comment is posted.
    let (pump, _session_guard) = build_pump(&fx, state, log, manager);
    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "the recovered issue lands, got {outcomes:?}"
    );

    // The load-bearing assertion: EXACTLY ONE result comment across the whole
    // replay-then-redrive, not two. This is the AC-17 at-most-once guarantee.
    assert_eq!(
        count_comments_of_kind(&fx.root, fx.issue_id, "result"),
        1,
        "AC-17: the result comment must post at most once across replay + redrive"
    );
}

/// Per-issue quarantine (#2): one poison issue must not brick the whole node.
///
/// A state.db with one INCONSISTENT issue (a `landing` substate persisted under
/// `implementing` — not a recoverable combination) plus one healthy `graphed`
/// issue. `recover` quarantines the bad one to `orchestrator-error` (and does
/// NOT return `Err`), then the pump still drives the healthy issue to `merged`.
#[test]
fn poison_issue_is_quarantined_and_healthy_issue_still_lands() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = open_state(&fx);

    // The poison issue: `implementing` phase carrying a `landing` substate. It
    // has a worker row (so plan_recovery is reached), and `plan_recovery` rejects
    // the phase/substate pairing as StateDbInconsistent.
    let poison_id = "poison-issue";
    state
        .upsert_issue(&IssueRow::new(poison_id, Phase::Implementing))
        .expect("seed poison issue");
    state
        .set_phase(
            poison_id,
            Phase::Implementing,
            Some(PhaseSubstate::RebaseStarted),
        )
        .expect("persist inconsistent substate");
    state
        .upsert_worker(&ActiveWorkerRow {
            worker_uuid: "poison-worker".to_owned(),
            issue_id: poison_id.to_owned(),
            role: WorkerRole::Implementer,
            round: 0,
            workspace_path: fx.root.join(".workspace").join("nonexistent"),
            pid: None,
            spawned_at: 1,
            last_heartbeat: 1,
        })
        .expect("register poison worker row");

    // The healthy issue: the fixture's graphed seed. Recovery must leave it for
    // the pump.
    state
        .upsert_issue(&IssueRow::new(&issue_id, Phase::Graphed))
        .expect("seed healthy graphed issue");

    // Recover: quarantines the poison issue, does NOT abort. The graphed issue is
    // untouched (NoAction), so it produces no RecoveryAction.
    let actions = recover(&state, &log, &manager, None).expect("recover must not abort");
    assert_eq!(actions.len(), 1, "only the poison issue is reconciled");
    match &actions[0] {
        RecoveryAction::Quarantined {
            issue_id: qid,
            reason: _,
        } => assert_eq!(qid, poison_id),
        other => panic!("expected Quarantined, got {other:?}"),
    }

    // The poison issue is now parked at orchestrator-error (undrivable).
    assert_eq!(
        state.get_issue(poison_id).unwrap().unwrap().phase,
        Phase::OrchestratorError
    );
    // The healthy issue is untouched, still graphed.
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::Graphed
    );

    // Startup did NOT abort: the pump drives the healthy issue to merged.
    let (pump, _session_guard) = build_pump(&fx, state, log, manager);
    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "the healthy issue must still land despite the poison sibling, got {outcomes:?}"
    );
    assert!(
        main_has_say_hi(&fx.root),
        "main must carry say_hi after the healthy issue landed"
    );
}

/// Landing-parks resume: a landing whose fast-forward is no longer valid.
///
/// The issue is persisted at `landing / rebase_done_bookmark_pending`, but `main`
/// has been advanced past the landing target so the move is no longer a
/// fast-forward. `resume_from` re-derives the FF ground truth and PARKS the issue
/// at `awaiting-human-merge` (via `LandingError::NotFastForward`, handled in-band
/// by the landing machine) rather than rewinding `main`. `main` is unmoved.
#[test]
fn landing_resume_parks_when_no_longer_a_fast_forward() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = open_state(&fx);

    // Stand up the implement workspace and run the worker, exactly as the pump
    // would before landing.
    let name = WorkspaceName::generate(Phase::Implementing, &issue_id, 0);
    let prepared = manager
        .prepare(&name, "main")
        .expect("prepare implement workspace");
    run(
        "bash",
        &[fake_implementer().to_str().unwrap()],
        prepared.path(),
    );
    let change = manager
        .entries()
        .expect("entries")
        .into_iter()
        .find(|e| e.name == name.as_str())
        .map(|e| e.working_copy_id)
        .expect("implement workspace has a working copy");

    // Reconstruct the pre-crash landing state: rebase ran, substate persisted as
    // `rebase_done_bookmark_pending`.
    manager
        .rebase(&change, "main")
        .expect("stage: rebase completed pre-crash");
    state
        .upsert_issue(&IssueRow::new(&issue_id, Phase::Landing))
        .expect("seed landing issue");
    state
        .set_phase(
            &issue_id,
            Phase::Landing,
            Some(PhaseSubstate::RebaseDoneBookmarkPending),
        )
        .expect("persist crashed-at substate");

    // Advance `main` OFF the landing base to a sibling commit, so the landing
    // target is no longer a fast-forward of the current `main`. Create a new
    // commit and move `main` onto it.
    run("jj", &["new", "main", "-m", "concurrent land"], &fx.root);
    run("jj", &["bookmark", "set", "main", "-r", "@"], &fx.root);
    let main_before = manager.bookmark_target("main").expect("read main");

    // Recover: resume_from sees main is no longer an ancestor of the target and
    // parks the issue for a human — NOT a quarantine, NOT a main rewind.
    let actions = recover(&state, &log, &manager, None).expect("recover must not abort");
    assert_eq!(
        actions,
        vec![RecoveryAction::ResumedLanding {
            issue_id: issue_id.clone(),
            outcome: LandingOutcome::AwaitingHumanMerge,
        }],
        "a non-fast-forward resume must park at awaiting-human-merge, got {actions:?}"
    );
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::AwaitingHumanMerge
    );

    // `main` is unmoved — the FF guard never rewound trunk.
    assert_eq!(
        manager.bookmark_target("main").expect("read main after"),
        main_before,
        "main must be unmoved after a parked resume"
    );
}
