//! A2 (#22) — the Adversary review phase wired into the build pump.
//!
//! These headless, Direct-fake-worker tests drive the whole
//! `QA-pass → adversary-review → (findings ? re-implement : converge) → land`
//! machine and prove the load-bearing behaviours:
//!
//! - **re-implement on findings:** an Adversary that flags a finding on round 0
//!   then signs off clean on round 1 → a `--kind blocker` is posted **once**
//!   (idempotent, content-addressed ledger), the issue re-implements at
//!   `round == 1`, and it finally converges → `Merged`;
//! - **clean-first converge:** a clean Adversary on round 0 converges → lands
//!   (the dogfood path, asserted here in isolation);
//! - **absent findings ≠ converged:** an Adversary that writes DONE but no
//!   `findings.jsonl` does NOT converge — the pump treats it as an incomplete
//!   review and poisons, proving A1's strict `Findings::from_done` is on the
//!   convergence path.
//!
//! All Direct fake workers, no live claude. Mirrors `dogfood.rs` /
//! `pump_adversarial.rs`.

mod common;

use std::path::Path;
use std::process::Command;

use common::{
    build_fixture, fake_adversary, fake_adversary_clean, fake_adversary_clean_record,
    fake_adversary_flag, fake_adversary_no_findings, fake_implementer, fake_implementer_qa_fail,
    unique_session, SessionGuard,
};
use orchestrator::config::{OrchestratorConfig, WorkerConfig};
use orchestrator::events::{read_all, EventLog, ORCHESTRATOR_DIR};
use orchestrator::pump::{BuildPump, IssueOutcome, MAX_ADVERSARY_ROUNDS};
use orchestrator::spawn::Spawner;
use orchestrator::state::{EventKind, IssueRow, Phase, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_crosslink_api::CrosslinkRepo;

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
/// absolute paths pass through argv resolution untouched), tight CI timeouts.
fn config_for(implementer: &Path, adversary: &Path) -> OrchestratorConfig {
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
        // A2's loop tests assert a first-clean-round land; pin n_rounds = 1 so
        // the default (2, the A3 detector) does not change their round/streak
        // expectations. The A3 needs-N-rounds behaviour has its own tests.
        convergence: orchestrator::config::ConvergenceConfig {
            n_rounds: 1,
            ..Default::default()
        },
        ..OrchestratorConfig::default()
    }
}

/// Build a pump over a fresh fixture with the given fake workers. Returns the
/// fixture, the pump, and the session guard (hold all three for the test).
fn pump_over(
    tag: &str,
    implementer: &Path,
    adversary: &Path,
) -> (common::Fixture, BuildPump, SessionGuard) {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");
    let (session, guard) = unique_session(tag);
    let spawner = Spawner::new(session, &fx.root, common::bwrap_pin());
    let pump = BuildPump::new(
        config_for(implementer, adversary),
        state,
        log,
        manager,
        spawner,
        crosslink,
    );
    (fx, pump, guard)
}

/// Re-implement-on-findings: the Adversary flags a finding on round 0, the issue
/// re-implements (round++), the clean round 1 converges → Merged. Asserts the
/// blocker was posted exactly once (idempotent) and the streak reset on findings.
#[test]
fn adversary_findings_reimplement_then_converge_to_merged() {
    let (fx, pump, _guard) = pump_over("adv-flag", &fake_implementer(), &fake_adversary_flag());
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let main_before = main_commit(&fx.root);

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "findings on r0 then a clean r1 must still converge → Merged, got {outcomes:?}"
    );

    // state.db authority: Merged, at round 1 (findings bumped the round once),
    // with the streak incremented by the single clean round that converged.
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let key = fx.issue_id.to_string();
    let issue = state.get_issue(&key).expect("read").expect("row");
    assert_eq!(issue.phase, Phase::Merged, "must converge to Merged");
    assert_eq!(
        issue.round, 1,
        "adversary findings must re-implement at round 1, got {}",
        issue.round
    );
    assert_eq!(
        issue.empty_round_streak, 1,
        "the converging clean round increments the streak to 1, got {}",
        issue.empty_round_streak
    );

    // main advanced to the re-implemented say_hi change.
    assert_ne!(main_commit(&fx.root), main_before, "main must advance");
    assert!(main_has_say_hi(&fx.root), "main must carry say_hi");

    // The finding was translated to a `--kind blocker` comment EXACTLY ONCE
    // (content-addressed ledger; per-finding rows carry finding_index >= 0).
    let posted = state
        .list_posted_artifacts(&key)
        .expect("list posted artifacts");
    let blockers: Vec<_> = posted.iter().filter(|p| p.finding_index >= 0).collect();
    assert_eq!(
        blockers.len(),
        1,
        "exactly one blocker must be posted (idempotent), got {posted:?}"
    );
    assert!(
        blockers[0].artifact_path.ends_with("findings.jsonl"),
        "the blocker derives from findings.jsonl, got {:?}",
        blockers[0]
    );

    // The re-implement was observable: a findings event reset the streak to 0,
    // and TWO implementer spawns ran (round 0 + the re-implement round 1).
    let events = read_all(orchestrator_dir.join("events.jsonl")).expect("read events");
    assert!(
        events.iter().any(|e| e.kind == EventKind::Transition
            && e.payload.get("to_phase").and_then(|v| v.as_str()) == Some("implementing")
            && e.payload.get("findings").and_then(|v| v.as_u64()) == Some(1)
            && e.payload.get("empty_round_streak").and_then(|v| v.as_u64()) == Some(0)),
        "a findings transition must reset empty_round_streak to 0, got {events:?}"
    );
    let implementer_spawns = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::Spawn
                && e.payload.get("role").and_then(|v| v.as_str()) == Some("implementer")
        })
        .count();
    assert!(
        implementer_spawns >= 2,
        "the next Implementer must have run (>= 2 implementer spawns), got {implementer_spawns}"
    );
    // At least one adversary spawn, and a convergence event for the clean round.
    assert!(
        events.iter().any(|e| e.kind == EventKind::Spawn
            && e.payload.get("role").and_then(|v| v.as_str()) == Some("adversary")),
        "an adversary must have been spawned"
    );
    assert!(
        events.iter().any(|e| e.kind == EventKind::Convergence
            && e.payload.get("converged").and_then(|v| v.as_bool()) == Some(true)),
        "a convergence event must record the clean round converging"
    );
}

/// Clean-first: a clean Adversary on round 0 converges → lands → Merged. No
/// blocker is posted, and the issue never leaves round 0.
#[test]
fn adversary_clean_first_round_converges_and_lands() {
    let (fx, pump, _guard) = pump_over("adv-clean", &fake_implementer(), &fake_adversary_clean());
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let main_before = main_commit(&fx.root);

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "a clean first round must converge → Merged, got {outcomes:?}"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let key = fx.issue_id.to_string();
    let issue = state.get_issue(&key).expect("read").expect("row");
    assert_eq!(issue.phase, Phase::Merged);
    assert_eq!(issue.round, 0, "a clean first round never re-implements");
    assert_eq!(issue.empty_round_streak, 1, "one clean round converged");

    assert_ne!(main_commit(&fx.root), main_before, "main must advance");
    assert!(main_has_say_hi(&fx.root), "main must carry say_hi");

    // No findings ⇒ no blocker comment posted (only the Implementer's result).
    let posted = state.list_posted_artifacts(&key).expect("list posted");
    assert!(
        posted.iter().all(|p| p.finding_index < 0),
        "a clean round must post no blocker, got {posted:?}"
    );
}

/// Absent findings ≠ converged: an Adversary that writes DONE but never a
/// `findings.jsonl` must NOT converge. The pump reads with the strict
/// `Findings::from_done`, treats the absent file as an incomplete review, and
/// poisons — proving the strict reader is on the convergence path (never
/// auto-landing a buggy change on a crashed Adversary).
#[test]
fn adversary_absent_findings_does_not_converge() {
    let (fx, pump, _guard) = pump_over(
        "adv-none",
        &fake_implementer(),
        &fake_adversary_no_findings(),
    );
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let main_before = main_commit(&fx.root);

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert!(
        outcomes
            .iter()
            .all(|(_, o)| !matches!(o, IssueOutcome::Merged)),
        "an incomplete Adversary (no findings.jsonl) must NEVER converge → Merged, got {outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|(_, o)| matches!(o, IssueOutcome::OrchestratorError)),
        "an incomplete Adversary review must poison, got {outcomes:?}"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let issue = state
        .get_issue(&fx.issue_id.to_string())
        .expect("read")
        .expect("row");
    assert_ne!(issue.phase, Phase::Merged, "must not be Merged");
    assert_eq!(
        issue.phase,
        Phase::OrchestratorError,
        "an absent-findings review poisons"
    );
    assert_eq!(
        main_commit(&fx.root),
        main_before,
        "main must NOT move for an unconverged issue"
    );
}

/// #1 (no orphan Implementer workspace): the Implementer workspace DIR must be
/// forgotten BEFORE adversary review, so a crash anywhere in the review window
/// can leave no orphan. The recording adversary captures the `.workspace/`
/// listing it sees while running; it must NOT contain an `implementing-*`
/// workspace. Landing still reaches `merged` (the change is durable in `.jj/`),
/// and nothing lingers under `.workspace/` at the end.
#[test]
fn implementer_workspace_forgotten_before_adversary_review() {
    let (fx, pump, _guard) = pump_over(
        "adv-record",
        &fake_implementer(),
        &fake_adversary_clean_record(),
    );

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "landing must still reach merged after forgetting the Implementer workspace, got {outcomes:?}"
    );
    assert!(main_has_say_hi(&fx.root), "main must carry say_hi");

    // The load-bearing assertion: while the Adversary ran, the Implementer
    // workspace was already gone.
    let seen = std::fs::read_to_string(
        fx.root
            .join(ORCHESTRATOR_DIR)
            .join("adversary-workspaces-seen.txt"),
    )
    .expect("the recording adversary must have written the workspace listing");
    assert!(
        !seen.contains("implementing-"),
        "no Implementer workspace may exist during adversary review (no orphan can outlive it), saw:\n{seen}"
    );

    // Nothing lingers under `.workspace/` after the run.
    let ws_root = fx.root.join(".workspace");
    if ws_root.exists() {
        let lingering: Vec<_> = std::fs::read_dir(&ws_root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            lingering.is_empty(),
            "no workspace may linger after a clean land, found {lingering:?}"
        );
    }
}

/// #2 (prior findings survive a crash): after a crash mid-review, recovery rolls
/// the issue back to `implementing` and the in-memory `prior_findings`
/// accumulator is gone — but the findings are durable as `--kind blocker`
/// comments. The pump must re-hydrate them so the re-entered round is NOT blind:
/// the Adversary sees a non-empty `prior_findings.json` and signs off on the
/// FIRST re-entered round, converging at that SAME round rather than re-flagging
/// and climbing another round.
///
/// Seeds the state a recovery pass leaves after a round-0 flag + crash: a durable
/// adversary blocker plus the issue at `implementing`, round 1. WITH re-hydration
/// the fake-flag adversary (which flags only when `prior_findings.json` is empty)
/// sees the prior finding and stays clean → converges at round 1. WITHOUT it, the
/// adversary would re-flag → round would climb to 2.
#[test]
fn rehydrated_prior_findings_make_reentry_converge_without_climbing_round() {
    let (fx, pump, _guard) =
        pump_over("adv-rehydrate", &fake_implementer(), &fake_adversary_flag());
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let key = fx.issue_id.to_string();

    // A durable adversary `--kind blocker` in the exact shape the pump posts one
    // (a `Finding::comment_body`, with the `[adversary]` role marker prepended by
    // `comment_write`). This models a round-0 flag whose in-memory accumulator was
    // lost to a crash.
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    crosslink
        .comment_write(
            fx.issue_id,
            "blocker",
            "[high] say_hi has no test covering the empty-string boundary\n\
             location: src/lib.rs:1\nevidence:\n- src/lib.rs",
            Some("adversary"),
        )
        .expect("post durable adversary blocker");

    // Seed the post-recovery re-entry state: implementing, round 1.
    {
        let seed = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db to seed");
        let mut issue = IssueRow::new(&key, Phase::Implementing);
        issue.round = 1;
        seed.upsert_issue(&issue).expect("seed re-entry issue");
    }

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "the re-entered issue must converge → merged, got {outcomes:?}"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let issue = state.get_issue(&key).expect("read").expect("row");
    assert_eq!(issue.phase, Phase::Merged);
    assert_eq!(
        issue.round, 1,
        "re-hydrated prior findings must let the adversary sign off on the re-entered round \
         (round stays 1); a blind re-entry would re-flag and climb to 2, got round {}",
        issue.round
    );
}

/// Minor (MAX_ADVERSARY_ROUNDS poison): a divergent Adversary that ALWAYS flags
/// (never signs off) must hit the round cap and poison to `orchestrator-error`,
/// with every workspace and worker row cleaned — never an infinite loop.
#[test]
fn divergent_adversary_poisons_at_round_cap_and_cleans_up() {
    let (fx, pump, _guard) = pump_over("adv-diverge", &fake_implementer(), &fake_adversary());
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let main_before = main_commit(&fx.root);

    let outcomes = pump.run_until_idle().expect("pump runs to idle");
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::OrchestratorError)],
        "a never-converging adversary must poison at the round cap, got {outcomes:?}"
    );

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let issue = state
        .get_issue(&fx.issue_id.to_string())
        .expect("read")
        .expect("row");
    assert_eq!(issue.phase, Phase::OrchestratorError, "must be poisoned");
    // The round climbed to the cap.
    assert!(
        issue.round >= MAX_ADVERSARY_ROUNDS - 1,
        "the round must have climbed to the cap, got {}",
        issue.round
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

/// Minor (empty_round_streak reset enforcement): a stale clean-round streak must
/// not survive a QA-fail re-drive (schema reset rules (b) QA fail and (c)
/// Implementer re-spawn). Seed a bogus non-zero streak, then drive a
/// QA-always-fails worker; after the retry budget poisons the issue, the streak
/// must read 0 — the reset fired, so A3's n-rounds detector can't be fooled by a
/// carried-over streak.
#[test]
fn qa_fail_and_respawn_reset_empty_round_streak() {
    let (fx, pump, _guard) = pump_over(
        "streak-reset",
        &fake_implementer_qa_fail(),
        &fake_adversary_clean(),
    );
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let key = fx.issue_id.to_string();

    // Seed the issue with a stale, non-zero streak at implementing.
    {
        let seed = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db to seed");
        let mut issue = IssueRow::new(&key, Phase::Implementing);
        issue.empty_round_streak = 7;
        seed.upsert_issue(&issue).expect("seed stale streak");
    }

    let _ = pump.run_until_idle().expect("pump runs to idle");

    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let issue = state.get_issue(&key).expect("read").expect("row");
    assert_eq!(
        issue.empty_round_streak, 0,
        "a stale streak must be reset to 0 across the QA-fail re-drive, got {}",
        issue.empty_round_streak
    );
}
