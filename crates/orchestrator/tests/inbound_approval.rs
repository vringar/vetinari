//! REQ-SWARM-1 — the inbound approval gate (spec §1.2), the security-critical
//! trust boundary that makes untrusted `xb:inbound` work **never auto-land**.
//!
//! These headless, fixture-backed tests drive the build pump's landing path
//! (`land_change`, the same public seam `pump_merger.rs` uses) and its resume
//! sweep (`tick`) against a *real* jj + crosslink repository — the `hello`
//! fixture from [`common::build_fixture`]. No live crossbridge peer, supervisor,
//! or socket is involved (the sandbox has none); inbound issues are minted as
//! plain `xb:inbound`-labeled crosslink issues, exactly the shape the embedded
//! server would create.
//!
//! Covered (the REQ-SWARM-1 guarantees):
//!
//! - **Park, never land — local FF mode (`tracker_remote` unset):** a converged
//!   `xb:inbound` issue parks at `phase:awaiting-inbound-approval` and `main` does
//!   NOT advance.
//! - **Park, never land — remote PR mode (`tracker_remote` set):** the SAME park,
//!   proving the gate sits before the mode-select and forecloses BOTH landing
//!   paths — no PR path is taken.
//! - **Approve → resume → land:** adding `inbound-approved:land` lets the pump's
//!   resume sweep re-drive the parked issue into landing (→ Merged), landing
//!   exactly the reviewed change from the durable handle.
//! - **Non-inbound unchanged (regression guard):** a converged NON-inbound issue
//!   lands to Merged exactly as before, untouched by the gate.
//! - **No double-answer across park → approve → merge:** an inbound issue answered
//!   at the park, then approved and merged, does NOT re-arm a second answer.
//! - **Crash while parked:** recovery leaves a parked inbound issue parked — never
//!   re-driven, never auto-landed.
//! - **Label-echo defense:** an inbound issue arriving with a peer-supplied
//!   `inbound-approved:land` (the upstream `handle_submit` echoes `SubmitIssue.labels`
//!   verbatim) has it — and every other privileged peer label — stripped on first
//!   adoption, so the gate STILL parks it for a real human approval.

mod common;

use std::path::Path;
use std::process::Command;

use common::{build_fixture, fake_implementer, Fixture};
use orchestrator::config::OrchestratorConfig;
use orchestrator::events::{EventLog, ORCHESTRATOR_DIR};
use orchestrator::pump::{BuildPump, IssueOutcome, INBOUND_APPROVED_LABEL};
use orchestrator::recovery::recover;
use orchestrator::spawn::Spawner;
use orchestrator::state::{IssueRow, Phase, PhaseSubstate, StateDb};
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

/// Create one `xb:inbound` crosslink issue (with the routing labels the answer
/// machine reads) and return its numeric id — the peer-submitted, untrusted shape.
fn create_inbound(root: &Path) -> i64 {
    let out = Command::new("crosslink")
        .args([
            "issue",
            "create",
            "inbound work from a peer",
            "-d",
            "peer-submitted, untrusted",
            "-l",
            "xb:inbound",
            "-l",
            "xb-source:firmware",
            "-l",
            "xb-ref:uuid-abc",
            "--quiet",
        ])
        .current_dir(root)
        .output()
        .expect("spawn crosslink issue create");
    assert!(
        out.status.success(),
        "crosslink issue create failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .and_then(|l| l.trim().parse().ok())
        .expect("parse created issue id")
}

/// Create one `xb:inbound` crosslink issue that ALSO carries the privileged
/// labels a hostile peer would smuggle in via `SubmitIssue.labels` (the upstream
/// echoes them onto the created issue): a pre-set `inbound-approved:land` (the
/// step-6 land-gate bypass), plus `phase:graphed` (so the pump's ingest adopts
/// it), `followup:proposed`, and a bogus `xb-status:*`. Returns its id.
fn create_preapproved_inbound(root: &Path) -> i64 {
    let out = Command::new("crosslink")
        .args([
            "issue",
            "create",
            "inbound work from a HOSTILE peer",
            "-d",
            "peer-submitted, untrusted, self-approved",
            "-l",
            "xb:inbound",
            "-l",
            "xb-source:firmware",
            "-l",
            "xb-ref:uuid-hostile",
            "-l",
            "xb-status:open",
            // The privileged labels a peer must NOT be able to set:
            "-l",
            "inbound-approved:land",
            "-l",
            "phase:graphed",
            "-l",
            "followup:proposed",
            "-l",
            "xb-status:answered",
            "--quiet",
        ])
        .current_dir(root)
        .output()
        .expect("spawn crosslink issue create");
    assert!(
        out.status.success(),
        "crosslink issue create failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .and_then(|l| l.trim().parse().ok())
        .expect("parse created issue id")
}

/// Build a pump over a fresh fixture with a default config (no worker is spawned —
/// these tests only exercise the landing gate + resume sweep). Returns the
/// fixture, pump, and session guard (hold all three for the test).
fn pump_over(tag: &str) -> (Fixture, BuildPump, SessionGuard) {
    pump_with_budget(tag, OrchestratorConfig::default().max_concurrent_agents)
}

/// Like [`pump_over`], but with an explicit `max_concurrent_agents` budget. A
/// budget of `0` lets a test run the pump's `tick` **ingest** step (which seeds
/// and sanitizes newly-adopted issues) while the drive step picks up nothing —
/// so the real ingest wiring is exercised without standing up a worker pipeline.
fn pump_with_budget(tag: &str, budget: u32) -> (Fixture, BuildPump, SessionGuard) {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");
    let (session, guard) = unique_session(tag);
    let spawner = Spawner::new(session, &fx.root, common::bwrap_pin());
    let config = OrchestratorConfig {
        worker_timeout_secs: 60,
        max_concurrent_agents: budget,
        ..OrchestratorConfig::default()
    };
    let pump = BuildPump::new(config, state, log, manager, spawner, crosslink);
    (fx, pump, guard)
}

/// Commit a worker change on `@` (a child of `main`) and seed a `state.db`
/// `Converged` row for `issue_id` — the phase the landing path starts from.
/// Returns the committed change id (the landing target).
fn stage_converged(fx: &Fixture, issue_id: i64) -> String {
    let state = StateDb::open(fx.root.join(ORCHESTRATOR_DIR).join("state.db")).expect("state.db");
    state
        .upsert_issue(&IssueRow::new(issue_id.to_string(), Phase::Converged))
        .expect("seed converged issue");
    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    wc_change_id(&fx.root)
}

/// Reopen the fixture's `state.db` for a fresh read of an issue row.
fn read_issue(fx: &Fixture, issue_id: i64) -> IssueRow {
    let state = StateDb::open(fx.root.join(ORCHESTRATOR_DIR).join("state.db")).expect("reopen");
    state
        .get_issue(&issue_id.to_string())
        .expect("read")
        .expect("row present")
}

/// REQ-SWARM-1 core guarantee (LOCAL FF mode, `tracker_remote` unset): a converged
/// `xb:inbound` issue parks at `awaiting-inbound-approval` and does NOT land —
/// `main` is not advanced.
#[test]
fn inbound_parks_and_does_not_land_local_mode() {
    let (fx, pump, _guard) = pump_over("inbound-park-local");
    let inbound = create_inbound(&fx.root);
    let change = stage_converged(&fx, inbound);
    let main_before = main_commit(&fx.root);

    let outcome = pump
        .land_change(inbound, &change)
        .expect("the gate is a handled outcome, not a hard error");
    assert_eq!(
        outcome,
        IssueOutcome::AwaitingInboundApproval,
        "an untrusted xb:inbound issue must park, never auto-land, got {outcome:?}"
    );

    // main is UNCHANGED — untrusted work never fast-forwarded trunk.
    assert_eq!(
        main_commit(&fx.root),
        main_before,
        "the inbound gate must leave main exactly where it was (no auto-land)"
    );

    // Authority: parked at awaiting-inbound-approval, with the reviewed change
    // durably stored so a later approval can land exactly it.
    let issue = read_issue(&fx, inbound);
    assert_eq!(issue.phase, Phase::AwaitingInboundApproval);
    assert_eq!(
        issue.landing_change.as_deref(),
        Some(change.as_str()),
        "the park must persist the reviewed change for the label-gated resume"
    );

    // A --kind blocker documents the required approval label for a human.
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let blockers = crosslink
        .list_comments(inbound)
        .expect("comments")
        .into_iter()
        .filter(|c| c.kind == "blocker")
        .count();
    assert!(
        blockers >= 1,
        "a parked inbound issue must carry a --kind blocker naming the approval label"
    );
}

/// REQ-SWARM-1 core guarantee (REMOTE PR mode, `tracker_remote` SET): the SAME
/// park holds — the gate sits BEFORE the mode-select, so remote mode never opens a
/// PR for untrusted work. `main` is untouched and no PR path is taken.
#[test]
fn inbound_parks_and_does_not_land_remote_mode() {
    let (fx, pump, _guard) = pump_over("inbound-park-remote");
    // Configure remote-PR landing mode. The gate short-circuits before the
    // mode-select reads this, so no GitHub token / PR opener is needed — proving
    // the park forecloses the remote path too. `config set` edits the tracked
    // `.crosslink/hook-config.json`, so fold that edit into `main` (describe + new
    // + advance the bookmark) to leave `@` a clean empty child of main for the
    // worker — exactly as the fixture's own seeding does.
    run(
        "crosslink",
        &[
            "config",
            "set",
            "tracker_remote",
            "git@github.com:example/repo.git",
        ],
        &fx.root,
    );
    run(
        "jj",
        &["describe", "-m", "configure remote landing mode"],
        &fx.root,
    );
    run("jj", &["new"], &fx.root);
    run("jj", &["bookmark", "set", "main", "-r", "@-"], &fx.root);

    let inbound = create_inbound(&fx.root);
    let change = stage_converged(&fx, inbound);
    let main_before = main_commit(&fx.root);

    let outcome = pump
        .land_change(inbound, &change)
        .expect("the gate is a handled outcome even in remote mode");
    assert_eq!(
        outcome,
        IssueOutcome::AwaitingInboundApproval,
        "remote mode must ALSO park untrusted work, never open a PR, got {outcome:?}"
    );
    assert_eq!(
        main_commit(&fx.root),
        main_before,
        "no landing path (local or remote) may touch main for untrusted work"
    );
    assert_eq!(
        read_issue(&fx, inbound).phase,
        Phase::AwaitingInboundApproval
    );
}

/// Approve → the pump's resume sweep re-drives the parked issue into landing (local
/// FF mode) → Merged, landing exactly the reviewed change. `main` advances.
#[test]
fn approval_label_lets_the_pump_resume_and_land() {
    let (fx, pump, _guard) = pump_over("inbound-approve");
    let inbound = create_inbound(&fx.root);
    let change = stage_converged(&fx, inbound);

    // First: park it (no approval yet).
    assert_eq!(
        pump.land_change(inbound, &change).expect("park"),
        IssueOutcome::AwaitingInboundApproval
    );
    let main_before = main_commit(&fx.root);

    // A human approves by adding the explicit label. Also drop the fixture seed
    // issue's `phase:graphed` label so the tick's ingest/drive has nothing else to
    // do — isolating the resume sweep.
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    crosslink
        .label_add(inbound, INBOUND_APPROVED_LABEL)
        .expect("apply approval label");
    crosslink
        .label_remove(fx.issue_id, "phase:graphed")
        .expect("neutralize the fixture seed issue");

    // The pump's tick resume sweep re-drives the approved issue into landing.
    let outcomes = pump.tick().expect("tick with an approved inbound issue");
    assert!(
        outcomes
            .iter()
            .any(|(id, o)| *id == inbound && *o == IssueOutcome::Merged),
        "an approved inbound issue must be resumed and landed by the pump: {outcomes:?}"
    );

    // main advanced to the reviewed change — the approved work landed.
    assert_ne!(
        main_commit(&fx.root),
        main_before,
        "after approval, main must fast-forward to the reviewed change"
    );
    assert_eq!(read_issue(&fx, inbound).phase, Phase::Merged);
}

/// Regression guard: a converged NON-inbound (locally-authored) issue lands to
/// Merged exactly as before — the gate never touches it.
#[test]
fn non_inbound_issue_lands_unchanged() {
    let (fx, pump, _guard) = pump_over("non-inbound");
    // The fixture's own seed issue is locally authored (no xb:inbound label).
    let change = stage_converged(&fx, fx.issue_id);
    let main_before = main_commit(&fx.root);

    let outcome = pump
        .land_change(fx.issue_id, &change)
        .expect("a non-inbound landing must succeed");
    assert_eq!(
        outcome,
        IssueOutcome::Merged,
        "a locally-authored converged issue must land exactly as before, got {outcome:?}"
    );
    assert_ne!(
        main_commit(&fx.root),
        main_before,
        "a non-inbound issue must still fast-forward main"
    );
    let issue = read_issue(&fx, fx.issue_id);
    assert_eq!(issue.phase, Phase::Merged);
    assert_eq!(
        issue.landing_change, None,
        "a non-inbound issue never stores an inbound landing_change handle"
    );
}

/// No double-answer across `park → approve → merge`: an inbound issue answered at
/// the park (simulated here by a stored `answer_sent` substate, since the sandbox
/// has no live transport), then approved and merged, must NOT re-arm a second
/// answer. The merge clears the substate; the resume path deliberately does not
/// re-fire the answer trigger, so it never returns to `answer_pending`.
#[test]
fn approve_and_merge_does_not_deliver_a_second_answer() {
    let (fx, pump, _guard) = pump_over("inbound-no-double-answer");
    let inbound = create_inbound(&fx.root);
    let change = stage_converged(&fx, inbound);

    // Park it.
    assert_eq!(
        pump.land_change(inbound, &change).expect("park"),
        IssueOutcome::AwaitingInboundApproval
    );

    // Simulate the peer having been answered ONCE at the park: the answer sweep
    // would have set `answer_sent`. (The real Unix-socket round-trip cannot run in
    // the sandbox, so we stand in its terminal state.)
    let state = StateDb::open(fx.root.join(ORCHESTRATOR_DIR).join("state.db")).expect("state.db");
    state
        .set_phase_substate(&inbound.to_string(), Some(PhaseSubstate::AnswerSent))
        .expect("simulate the park-time answer delivery");
    assert_eq!(
        read_issue(&fx, inbound).phase_substate.as_deref(),
        Some(PhaseSubstate::AnswerSent.as_str())
    );

    // Approve + neutralize the fixture seed issue, then resume via a tick.
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    crosslink
        .label_add(inbound, INBOUND_APPROVED_LABEL)
        .expect("approve");
    crosslink
        .label_remove(fx.issue_id, "phase:graphed")
        .expect("neutralize seed");

    let outcomes = pump.tick().expect("tick resumes the approved issue");
    assert!(
        outcomes
            .iter()
            .any(|(id, o)| *id == inbound && *o == IssueOutcome::Merged),
        "the approved issue must land: {outcomes:?}"
    );

    // The load-bearing assertion: after park (answered) → approve → merge, the
    // issue is Merged and its substate was NOT re-armed to `answer_pending`. A
    // resume that (wrongly) re-fired the answer trigger would leave it
    // `answer_pending` here (landing cleared the substate to None first).
    let issue = read_issue(&fx, inbound);
    assert_eq!(issue.phase, Phase::Merged);
    assert_ne!(
        issue.phase_substate.as_deref(),
        Some(PhaseSubstate::AnswerPending.as_str()),
        "the merge must NOT re-arm a second answer (park → approve → merge answers once)"
    );
    assert_eq!(
        issue.phase_substate, None,
        "landing clears the substate; the resume must not re-arm it"
    );
}

/// Answer exactly once even when the park-time delivery FAILED: an inbound issue
/// parks, its park answer never reaches the peer (`answer_unreachable`), a human
/// approves, and the tick lands it. The merge clears the answer substate the retry
/// sweep keys off — so without the re-arm the peer would be answered ZERO times.
/// Assert the merged issue is left `answer_pending` (re-armed, delivered by the
/// step-3 sweep), NOT lost, and its `answer_attempts` retry bookkeeping survives.
#[test]
fn approve_and_merge_re_arms_an_undelivered_park_answer() {
    let (fx, pump, _guard) = pump_over("inbound-unreachable-then-approve");
    let inbound = create_inbound(&fx.root);
    let change = stage_converged(&fx, inbound);

    // Park it.
    assert_eq!(
        pump.land_change(inbound, &change).expect("park"),
        IssueOutcome::AwaitingInboundApproval
    );

    // Simulate the park-time answer delivery FAILING (peer offline): the sweep
    // would have recorded `answer_unreachable` and bumped `answer_attempts`. (No
    // live crossbridge peer exists in the sandbox, so we stand in that state.)
    let state = StateDb::open(fx.root.join(ORCHESTRATOR_DIR).join("state.db")).expect("state.db");
    let attempts = state
        .record_answer_unreachable(&inbound.to_string())
        .expect("simulate a failed park-time delivery");
    assert_eq!(attempts, 1, "one failed attempt recorded");
    assert_eq!(
        read_issue(&fx, inbound).phase_substate.as_deref(),
        Some(PhaseSubstate::AnswerUnreachable.as_str())
    );

    // Approve + neutralize the fixture seed issue, then resume via a tick.
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    crosslink
        .label_add(inbound, INBOUND_APPROVED_LABEL)
        .expect("approve");
    crosslink
        .label_remove(fx.issue_id, "phase:graphed")
        .expect("neutralize seed");

    let outcomes = pump.tick().expect("tick resumes the approved issue");
    assert!(
        outcomes
            .iter()
            .any(|(id, o)| *id == inbound && *o == IssueOutcome::Merged),
        "the approved issue must land: {outcomes:?}"
    );

    // The load-bearing assertion: the merge did NOT lose the outstanding answer.
    // The never-delivered park answer is re-armed to `answer_pending` so the
    // answer sweep delivers it at the merge terminal — the peer is eventually
    // answered exactly once, not zero times.
    let issue = read_issue(&fx, inbound);
    assert_eq!(issue.phase, Phase::Merged);
    assert_eq!(
        issue.phase_substate.as_deref(),
        Some(PhaseSubstate::AnswerPending.as_str()),
        "an undelivered park answer must be re-armed across the merge, not erased"
    );
    // Retry bookkeeping is preserved (not reset) — the re-arm is a plain substate
    // write, so the attempt bound still holds and cannot be reset into a spin.
    assert_eq!(
        issue.answer_attempts, 1,
        "the re-arm must preserve answer_attempts, not reset the retry bound"
    );
}

/// Crash mid-resume-land completes from the durable `landing_change` (FIX 2): an
/// approved inbound issue crashed at a `Landing` substate with its human-reviewed
/// change persisted in `issues.landing_change` and its Implementer workspace already
/// forgotten. The workspace scan can no longer re-derive the change — recovery must
/// complete the landing from the STORED change (landing exactly it), not quarantine.
#[test]
fn recovery_completes_approved_inbound_land_from_stored_change() {
    let (fx, _pump, _guard) = pump_over("inbound-crash-mid-land");
    let inbound = create_inbound(&fx.root);
    let change = stage_converged(&fx, inbound);
    let main_before = main_commit(&fx.root);

    // Simulate the crash state: the approval sweep had re-driven the issue into
    // landing (Landing/RebaseStarted) with the reviewed change persisted, then the
    // process died. There is NO `implementing` workspace (landing forgot it before
    // review), so the workspace scan cannot re-derive the change.
    let state = StateDb::open(fx.root.join(ORCHESTRATOR_DIR).join("state.db")).expect("state.db");
    state
        .set_landing_change(&inbound.to_string(), &change)
        .expect("persist the reviewed change (as the park does)");
    state
        .set_phase(
            &inbound.to_string(),
            Phase::Landing,
            Some(PhaseSubstate::RebaseStarted),
        )
        .expect("simulate a crash mid-resume-land");

    // Run crash recovery.
    let log = EventLog::open(fx.root.join(ORCHESTRATOR_DIR)).expect("events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    recover(&state, &log, &manager, Some(&crosslink)).expect("recovery must not error");

    // Recovery completed the landing from the stored change — Merged, not
    // quarantined at orchestrator-error — and `main` advanced to exactly it.
    let issue = read_issue(&fx, inbound);
    assert_eq!(
        issue.phase,
        Phase::Merged,
        "recovery must complete the land from the durable landing_change, not quarantine"
    );
    assert_ne!(
        main_commit(&fx.root),
        main_before,
        "the stored, human-approved change must land — main fast-forwards to it"
    );
}

/// Crash while parked: recovery leaves a parked `xb:inbound` issue parked — never
/// re-driven back to a drivable phase, never auto-landed. Mirrors how
/// `awaiting-human-merge` (also terminal) is left untouched by recovery.
#[test]
fn recovery_leaves_a_parked_inbound_issue_parked() {
    let (fx, pump, _guard) = pump_over("inbound-crash-parked");
    let inbound = create_inbound(&fx.root);
    let change = stage_converged(&fx, inbound);

    // Park it, then simulate the post-park armed answer (the realistic parked
    // state: terminal phase carrying an answer substate).
    assert_eq!(
        pump.land_change(inbound, &change).expect("park"),
        IssueOutcome::AwaitingInboundApproval
    );
    let state = StateDb::open(fx.root.join(ORCHESTRATOR_DIR).join("state.db")).expect("state.db");
    state
        .set_phase_substate(&inbound.to_string(), Some(PhaseSubstate::AnswerPending))
        .expect("arm the answer as the park would");
    let main_before = main_commit(&fx.root);

    // Run crash recovery (the startup scan).
    let log = EventLog::open(fx.root.join(ORCHESTRATOR_DIR)).expect("events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    recover(&state, &log, &manager, Some(&crosslink)).expect("recovery must not error");

    // Still parked: not rolled back to implementing (re-driven), not landed.
    let issue = read_issue(&fx, inbound);
    assert_eq!(
        issue.phase,
        Phase::AwaitingInboundApproval,
        "recovery must leave a parked inbound issue parked, not re-drive it"
    );
    assert_eq!(
        issue.landing_change.as_deref(),
        Some(change.as_str()),
        "the reviewed-change handle must survive recovery for a later approval"
    );
    assert_eq!(
        main_commit(&fx.root),
        main_before,
        "recovery must never auto-land untrusted parked work"
    );
}

/// Label-echo defense (the upstream trust gap): the embedded crossbridge server
/// copies a peer's `SubmitIssue.labels` verbatim onto the issue it creates, so a
/// hostile peer can pre-stamp its OWN `inbound-approved:land`. Left in place, the
/// step-6 land gate would misread that peer label as a human's approval and
/// auto-land untrusted work. The pump's first-adoption sanitize (run in `tick`'s
/// ingest) must strip it — and every other privileged peer label — so the gate
/// STILL parks the issue for a real human approval.
#[test]
fn ingest_strips_a_peer_preset_approval_so_the_gate_still_parks() {
    // Budget 0: `tick` runs ingest (seed + sanitize) but drives nothing, so the
    // REAL adoption wiring is exercised without a worker pipeline.
    let (fx, pump, _guard) = pump_with_budget("inbound-label-echo", 0);
    let inbound = create_preapproved_inbound(&fx.root);

    // First adoption: ingest seeds the issue AND sanitizes its peer labels.
    let outcomes = pump
        .tick()
        .expect("tick ingests + sanitizes the inbound issue");
    assert!(
        outcomes.is_empty(),
        "budget 0 must drive nothing; ingest only: {outcomes:?}"
    );

    // The privileged peer labels are GONE from crosslink...
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let labels = crosslink.read_issue(inbound).expect("read inbound").labels;
    assert!(
        !labels.iter().any(|l| l == INBOUND_APPROVED_LABEL),
        "the peer's pre-set land-approval MUST be stripped: {labels:?}"
    );
    assert!(
        !labels.iter().any(|l| l == "followup:proposed"),
        "a peer must not raise the follow-up marker: {labels:?}"
    );
    assert!(
        !labels.iter().any(|l| l == "xb-status:answered"),
        "a peer must not set a bogus xb-status: {labels:?}"
    );
    // ...while the server's own + the section-chief's legitimate labels REMAIN.
    for keep in [
        "xb:inbound",
        "xb-source:firmware",
        "xb-ref:uuid-hostile",
        "xb-status:open",
    ] {
        assert!(
            labels.iter().any(|l| l == keep),
            "the sanitize must preserve the legitimate label `{keep}`: {labels:?}"
        );
    }

    // The load-bearing consequence: converge + land now PARKS for a human, exactly
    // as an un-approved inbound issue must — the peer's self-approval bought nothing.
    let change = stage_converged(&fx, inbound);
    let main_before = main_commit(&fx.root);
    let outcome = pump
        .land_change(inbound, &change)
        .expect("land is a handled outcome");
    assert_eq!(
        outcome,
        IssueOutcome::AwaitingInboundApproval,
        "a peer-approved inbound issue must STILL park after sanitize, got {outcome:?}"
    );
    assert_eq!(
        main_commit(&fx.root),
        main_before,
        "untrusted work must not auto-land off a peer-supplied approval"
    );
}
