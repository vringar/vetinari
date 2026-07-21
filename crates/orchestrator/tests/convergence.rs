//! A3 (#23) — the real convergence detector wired into the build pump.
//!
//! A2 landed a placeholder (`streak >= 1`); A3 replaces it with REQ-10's rule:
//! **N consecutive clean Adversary rounds on the SAME change**. The change is
//! resolved to an immutable jj commit id for the whole review, so it cannot move
//! between rounds — the consecutive-clean streak alone captures "same unchanged
//! change" (REQ-10's `last_diff_hash` guard is vestigial in this synchronous
//! model). These headless, Direct-fake-worker tests prove the load-bearing A3
//! behaviours the dogfoods (pinned to `n_rounds = 1`) can't:
//!
//! - **needs-N-rounds:** with `n_rounds = 2` an always-clean Adversary must be
//!   re-spawned TWICE (two clean re-review rounds) before converging → Merged;
//!   it must NOT converge after a single clean round, and the Implementer must
//!   NOT re-run between the two clean re-reviews (a re-review, not a re-implement).
//! - **streak-reset:** a finding mid-streak resets `empty_round_streak`, so
//!   convergence needs a FRESH N consecutive clean rounds again.
//! - **bounded clean-loop:** an Adversary that never reaches N consecutive clean
//!   rounds hits the round cap and poisons to `orchestrator-error` — never an
//!   infinite re-review loop — with main unmoved and every worker/workspace
//!   cleaned.
//!
//! All Direct fake workers, no live claude. Mirrors `pump_adversary_loop.rs`.

mod common;

use std::path::Path;
use std::process::Command;

use common::{
    build_fixture, fake_adversary_clean, fake_adversary_flag_midstreak, fake_implementer,
};
use orchestrator::config::{ConvergenceConfig, OrchestratorConfig, WorkerConfig};
use orchestrator::events::{read_all, EventLog, ORCHESTRATOR_DIR};
use orchestrator::pump::{BuildPump, IssueOutcome, MAX_ADVERSARY_ROUNDS};
use orchestrator::spawn::{SandboxPin, Spawner};
use orchestrator::state::{EventKind, EventRow, Phase, StateDb};
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

fn main_commit(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["log", "-r", "main", "--no-graph", "-T", "commit_id"])
        .current_dir(cwd)
        .output()
        .expect("jj log for main");
    assert!(out.status.success(), "jj log must succeed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn main_has_say_hi(cwd: &Path) -> bool {
    let out = Command::new("jj")
        .args(["file", "show", "-r", "main", "src/lib.rs"])
        .current_dir(cwd)
        .output()
        .expect("jj file show main:src/lib.rs");
    assert!(out.status.success(), "jj file show must succeed");
    String::from_utf8_lossy(&out.stdout).contains("fn say_hi")
}

/// A config dispatching the given Direct implementer + adversary scripts (their
/// absolute paths pass through argv resolution untouched), with `n_rounds`
/// convergence and tight CI timeouts.
fn config_for(implementer: &Path, adversary: &Path, n_rounds: u32) -> OrchestratorConfig {
    OrchestratorConfig {
        worker: WorkerConfig {
            argv: vec![
                "bash".to_owned(),
                implementer.to_string_lossy().into_owned(),
            ],
            adversary_argv: vec!["bash".to_owned(), adversary.to_string_lossy().into_owned()],
            ..WorkerConfig::default()
        },
        worker_timeout_secs: 60,
        convergence: ConvergenceConfig {
            n_rounds,
            ..Default::default()
        },
        ..OrchestratorConfig::default()
    }
}

/// Build a pump over a fresh fixture with the given fake workers + `n_rounds`.
fn pump_over(
    tag: &str,
    implementer: &Path,
    adversary: &Path,
    n_rounds: u32,
) -> (common::Fixture, BuildPump, SessionGuard) {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");
    let (session, guard) = unique_session(tag);
    let spawner = Spawner::new(session, &fx.root, SandboxPin::new("unused-direct"));
    let pump = BuildPump::new(
        config_for(implementer, adversary, n_rounds),
        state,
        log,
        manager,
        spawner,
        crosslink,
    );
    (fx, pump, guard)
}

/// Count spawn events for a role from the events.jsonl mirror.
fn spawns_for_role(events: &[EventRow], role: &str) -> usize {
    events
        .iter()
        .filter(|e| {
            e.kind == EventKind::Spawn
                && e.payload.get("role").and_then(|v| v.as_str()) == Some(role)
        })
        .count()
}

/// The ordered `empty_round_streak` values recorded on each convergence event.
fn convergence_streaks(events: &[EventRow]) -> Vec<u64> {
    events
        .iter()
        .filter(|e| e.kind == EventKind::Convergence)
        .filter_map(|e| e.payload.get("empty_round_streak").and_then(|v| v.as_u64()))
        .collect()
}

/// needs-N-rounds: with `n_rounds = 2` an always-clean Adversary is re-spawned
/// TWICE — two clean re-review rounds — before converging → Merged. It must
/// NOT converge on the first clean round, and the Implementer must NOT re-run
/// between the two clean re-reviews (round stays 0, one implementer spawn).
#[test]
fn needs_two_clean_rounds_before_converging() {
    let (fx, pump, _guard) = pump_over("conv-2r", &fake_implementer(), &fake_adversary_clean(), 2);
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let key = fx.issue_id.to_string();
    let main_before = main_commit(&fx.root);

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "two clean rounds (n_rounds=2) must converge → Merged, got {outcomes:?}"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let issue = state.get_issue(&key).expect("read").expect("row");
    assert_eq!(issue.phase, Phase::Merged);
    assert_eq!(
        issue.round, 0,
        "a re-review is NOT a re-implement — the round must stay 0, got {}",
        issue.round
    );
    assert_eq!(
        issue.empty_round_streak, 2,
        "convergence at n_rounds=2 requires the streak to reach exactly 2, got {}",
        issue.empty_round_streak
    );

    let events = read_all(orchestrator_dir.join("events.jsonl")).expect("read events");
    // The Adversary ran TWICE (two clean rounds); the Implementer ran ONCE (no
    // re-implement between the clean re-reviews).
    assert_eq!(
        spawns_for_role(&events, "adversary"),
        2,
        "the always-clean Adversary must be re-spawned for a second clean round"
    );
    assert_eq!(
        spawns_for_role(&events, "implementer"),
        1,
        "the Implementer must NOT re-run between the two clean adversary rounds"
    );
    // It did NOT converge after only one clean round: the streak-1 convergence
    // event says converged=false, and only the streak-2 event says true.
    assert_eq!(
        convergence_streaks(&events),
        vec![1, 2],
        "the streak must climb 1 → 2 across two clean rounds, got {:?}",
        convergence_streaks(&events)
    );
    assert!(
        events.iter().any(|e| e.kind == EventKind::Convergence
            && e.payload.get("empty_round_streak").and_then(|v| v.as_u64()) == Some(1)
            && e.payload.get("converged").and_then(|v| v.as_bool()) == Some(false)),
        "one clean round must NOT converge (needs 2), got {events:?}"
    );
    assert!(
        events.iter().any(|e| e.kind == EventKind::Convergence
            && e.payload.get("empty_round_streak").and_then(|v| v.as_u64()) == Some(2)
            && e.payload.get("converged").and_then(|v| v.as_bool()) == Some(true)),
        "the second clean round must converge"
    );

    assert_ne!(main_commit(&fx.root), main_before, "main must advance");
    assert!(main_has_say_hi(&fx.root), "main must carry say_hi");
}

/// streak-reset: a finding mid-streak resets `empty_round_streak` to 0, so
/// convergence needs a FRESH N (=2) consecutive clean rounds again. The
/// mid-streak fixture is CLEAN (streak → 1), then FLAGS (reset + re-implement),
/// then CLEAN forever — so it converges only after two fresh clean rounds on the
/// re-implemented change.
#[test]
fn finding_midstreak_resets_streak_and_requires_fresh_n_rounds() {
    let (fx, pump, _guard) = pump_over(
        "conv-reset",
        &fake_implementer(),
        &fake_adversary_flag_midstreak(),
        2,
    );
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let key = fx.issue_id.to_string();
    let main_before = main_commit(&fx.root);

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "a mid-streak finding then two fresh clean rounds must still converge, got {outcomes:?}"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let issue = state.get_issue(&key).expect("read").expect("row");
    assert_eq!(issue.phase, Phase::Merged);
    assert_eq!(
        issue.round, 1,
        "the mid-streak finding must re-implement exactly once (round 1), got {}",
        issue.round
    );
    assert_eq!(
        issue.empty_round_streak, 2,
        "convergence after the reset still requires two fresh clean rounds, got {}",
        issue.empty_round_streak
    );

    let events = read_all(orchestrator_dir.join("events.jsonl")).expect("read events");
    // The finding reset the streak to 0 on the way back to implementing.
    assert!(
        events.iter().any(|e| e.kind == EventKind::Transition
            && e.payload.get("to_phase").and_then(|v| v.as_str()) == Some("implementing")
            && e.payload.get("findings").and_then(|v| v.as_u64()) == Some(1)
            && e.payload.get("empty_round_streak").and_then(|v| v.as_u64()) == Some(0)),
        "a mid-streak finding must reset empty_round_streak to 0, got {events:?}"
    );
    // The streak sequence proves it: climbed to 1 (pre-finding clean), then after
    // the reset climbed 1 → 2 on two fresh clean rounds.
    assert_eq!(
        convergence_streaks(&events),
        vec![1, 1, 2],
        "streak must go 1 (pre-finding), then reset and climb 1 → 2, got {:?}",
        convergence_streaks(&events)
    );
    // Two implementer spawns: the initial round 0 and the post-finding re-implement.
    assert_eq!(
        spawns_for_role(&events, "implementer"),
        2,
        "the mid-streak finding must trigger exactly one re-implement (2 implementer spawns)"
    );

    assert_ne!(main_commit(&fx.root), main_before, "main must advance");
    assert!(main_has_say_hi(&fx.root), "main must carry say_hi");
}

/// bounded clean-loop: an Adversary that never reaches N consecutive clean rounds
/// must poison rather than loop forever. With `n_rounds` set ABOVE the round cap
/// and an always-clean Adversary, the clean re-review loop exhausts
/// `MAX_ADVERSARY_ROUNDS` without ever reaching N — so it poisons to
/// `orchestrator-error`, leaves main unmoved, and cleans up every worker row and
/// workspace.
#[test]
fn clean_rereview_loop_is_bounded_and_poisons() {
    // n_rounds beyond the cap can never be reached by the bounded re-review loop.
    let n_rounds = (MAX_ADVERSARY_ROUNDS + 1) as u32;
    let (fx, pump, _guard) = pump_over(
        "conv-unbounded",
        &fake_implementer(),
        &fake_adversary_clean(),
        n_rounds,
    );
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let main_before = main_commit(&fx.root);

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::OrchestratorError)],
        "an Adversary that never reaches N consecutive clean rounds must poison, got {outcomes:?}"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let issue = state
        .get_issue(&fx.issue_id.to_string())
        .expect("read")
        .expect("row");
    assert_eq!(issue.phase, Phase::OrchestratorError, "must be poisoned");

    // The clean re-review loop ran the FULL cap of rounds (streak climbed toward,
    // but never reached, n_rounds) before poisoning.
    let events = read_all(orchestrator_dir.join("events.jsonl")).expect("read events");
    assert_eq!(
        spawns_for_role(&events, "adversary"),
        MAX_ADVERSARY_ROUNDS as usize,
        "the bounded clean re-review loop must run exactly MAX_ADVERSARY_ROUNDS rounds"
    );
    assert!(
        convergence_streaks(&events)
            .iter()
            .all(|&s| s < n_rounds as u64),
        "no clean round may ever reach n_rounds (it poisons instead), got {:?}",
        convergence_streaks(&events)
    );

    // main never moved, no worker rows leaked, no workspace lingers.
    assert_eq!(
        main_commit(&fx.root),
        main_before,
        "a poisoned issue must never advance main"
    );
    assert!(
        state.list_active_workers().expect("workers").is_empty(),
        "no active_workers row may leak after poison"
    );
    let ws_root = fx.root.join(".workspace");
    if ws_root.exists() {
        let lingering: Vec<_> = std::fs::read_dir(&ws_root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            lingering.is_empty(),
            "no workspace may linger after poison, found {lingering:?}"
        );
    }
}
