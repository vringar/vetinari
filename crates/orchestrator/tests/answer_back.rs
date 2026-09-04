//! Fixture-backed crossbridge **answer-back** behavioral tests (spec §1.3/§1.4).
//!
//! These drive the answer sweep ([`orchestrator::answer::deliver_pending`]) and
//! the crash-recovery close reconciliation ([`orchestrator::recovery::recover`])
//! against a *real* crosslink repo — the `hello` fixture from
//! [`common::build_fixture`] — with a **fake** [`AnswerTransport`] injected in
//! place of the real Unix-socket round-trip (the sandbox has no crossbridge peer
//! or supervisor, so every answer-machine test uses the fake seam).
//!
//! Covered here (the reviewer's fan-out / traversal / zombie findings):
//!
//! - **Per-tick fan-out cap (review #1):** with more due answers than
//!   [`MAX_ANSWER_DELIVERIES_PER_TICK`], only that many reach the wire in one
//!   sweep; the rest wait for the next tick.
//! - **Untrusted slug validation (review #2):** an `xb-source:` slug that is not a
//!   valid crossbridge slug is rejected BEFORE any socket path is built — the
//!   transport is never called and the issue is parked (not retried).
//! - **Crash-window zombie close (review #3):** an answered (`answer_sent`) inbound
//!   issue left open by a crash between the substate persist and the close is
//!   reconciled by recovery, idempotently.

mod common;

use std::cell::RefCell;
use std::path::Path;
use std::process::Command;

use common::{build_fixture, Fixture};
use orchestrator::answer::{
    deliver_pending, AnswerAction, AnswerTransport, MAX_ANSWER_ATTEMPTS,
    MAX_ANSWER_DELIVERIES_PER_TICK,
};
use orchestrator::events::{EventLog, ORCHESTRATOR_DIR};
use orchestrator::recovery::{recover, RecoveryAction};
use orchestrator::state::{IssueRow, Phase, PhaseSubstate, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_crossbridge_api::{AnswerOutcome, AnswerReq, CrossbridgeError};
use vetinari_crosslink_api::CrosslinkRepo;

/// A fake [`AnswerTransport`] that records every [`AnswerReq`] it is handed and
/// returns a scripted outcome — success by default, or a `PeerUnreachable` when
/// `fail` is set. No socket is ever touched.
struct FakeTransport {
    calls: RefCell<Vec<AnswerReq>>,
    fail: bool,
}

impl FakeTransport {
    fn ok() -> Self {
        FakeTransport {
            calls: RefCell::new(Vec::new()),
            fail: false,
        }
    }

    fn call_count(&self) -> usize {
        self.calls.borrow().len()
    }
}

impl AnswerTransport for FakeTransport {
    fn answer(&self, req: &AnswerReq) -> Result<AnswerOutcome, CrossbridgeError> {
        self.calls.borrow_mut().push(req.clone());
        if self.fail {
            return Err(CrossbridgeError::PeerUnreachable {
                peer: req.peer_slug.clone(),
                socket: req.socket_root.join(&req.peer_slug),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "fake offline peer",
                )),
            });
        }
        Ok(AnswerOutcome {
            remote_issue_id: 9000 + req.source_uuid.len() as i64,
        })
    }
}

/// Open a fresh `state.db` + `events.jsonl` under the fixture's `.orchestrator/`.
fn open_state(fx: &Fixture) -> (StateDb, EventLog) {
    let orch = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orch.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orch).expect("open events.jsonl");
    (state, log)
}

/// Create one `xb:inbound` crosslink issue with the given source slug + ref, and
/// return its numeric id. Uses the `crosslink` CLI (the same test-support path the
/// fixture's own seed issue uses); the labels are what the answer machine routes on.
fn create_inbound(root: &Path, source_slug: &str, source_ref: &str) -> i64 {
    let out = Command::new("crosslink")
        .args([
            "issue",
            "create",
            "inbound work from a peer",
            "-d",
            "peer-submitted",
            "-l",
            "xb:inbound",
            "-l",
            &format!("xb-source:{source_slug}"),
            "-l",
            &format!("xb-ref:{source_ref}"),
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

/// Upsert a terminal (`merged`) `state.db` row for `issue_id` carrying `substate`.
fn upsert_terminal(state: &StateDb, issue_id: i64, substate: PhaseSubstate) {
    let mut row = IssueRow::new(issue_id.to_string(), Phase::Merged);
    row.phase_substate = Some(substate.as_str().to_owned());
    state.upsert_issue(&row).expect("upsert terminal issue row");
}

/// Review #1 — the sweep delivers at most [`MAX_ANSWER_DELIVERIES_PER_TICK`]
/// answers per tick, even when more are due. A burst of newly-terminal inbound
/// issues to (fake) peers must not fan out unbounded on the pump thread.
#[test]
fn sweep_caps_deliveries_per_tick() {
    let fx = build_fixture();
    let (state, log) = open_state(&fx);
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let socket_root = fx.root.join("run");

    // Five inbound issues, all freshly answer_pending — more than the cap.
    let n = 5usize;
    for i in 0..n {
        let id = create_inbound(&fx.root, "firmware", &format!("uuid-{i}"));
        upsert_terminal(&state, id, PhaseSubstate::AnswerPending);
    }
    assert!(
        n > MAX_ANSWER_DELIVERIES_PER_TICK,
        "test needs more than the cap"
    );

    let transport = FakeTransport::ok();
    let actions = deliver_pending(
        &state,
        &crosslink,
        &log,
        &transport,
        "firmware",
        &socket_root,
        300,
        1_000_000,
    )
    .expect("sweep");

    // Exactly the cap reached the wire this tick.
    assert_eq!(
        transport.call_count(),
        MAX_ANSWER_DELIVERIES_PER_TICK,
        "one tick must deliver at most the per-tick cap"
    );
    let answered = actions
        .iter()
        .filter(|a| matches!(a, AnswerAction::Answered { .. }))
        .count();
    assert_eq!(answered, MAX_ANSWER_DELIVERIES_PER_TICK);

    // The remainder are still answer_pending (deferred), and the delivered ones
    // are now answer_sent — the sweep made forward progress without freezing.
    let rows = state.list_issues().expect("list");
    let sent = rows
        .iter()
        .filter(|r| r.phase_substate.as_deref() == Some(PhaseSubstate::AnswerSent.as_str()))
        .count();
    let pending = rows
        .iter()
        .filter(|r| r.phase_substate.as_deref() == Some(PhaseSubstate::AnswerPending.as_str()))
        .count();
    assert_eq!(sent, MAX_ANSWER_DELIVERIES_PER_TICK);
    assert_eq!(pending, n - MAX_ANSWER_DELIVERIES_PER_TICK);

    // A second tick drains more, proving the deferred work is picked up later.
    let transport2 = FakeTransport::ok();
    deliver_pending(
        &state,
        &crosslink,
        &log,
        &transport2,
        "firmware",
        &socket_root,
        300,
        1_000_100,
    )
    .expect("second sweep");
    assert_eq!(transport2.call_count(), MAX_ANSWER_DELIVERIES_PER_TICK);
}

/// Review #2 — an `xb-source:` slug that is not a valid crossbridge slug (here the
/// `..` path-traversal segment) is rejected before any socket path is built: the
/// transport is NEVER called, and the issue is parked (bound-exhausted, a blocker
/// posted) rather than retried as a transient unreachable.
#[test]
fn traversal_slug_is_rejected_without_delivery() {
    let fx = build_fixture();
    let (state, log) = open_state(&fx);
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let socket_root = fx.root.join("run");

    // A traversal segment as the peer slug — must never become a socket path.
    let id = create_inbound(&fx.root, "..", "uuid-bad");
    upsert_terminal(&state, id, PhaseSubstate::AnswerPending);

    let transport = FakeTransport::ok();
    let actions = deliver_pending(
        &state,
        &crosslink,
        &log,
        &transport,
        "firmware",
        &socket_root,
        300,
        1_000_000,
    )
    .expect("sweep");

    // The wire was never touched — no path out of socket_root was formed.
    assert_eq!(
        transport.call_count(),
        0,
        "an invalid slug must never reach the transport"
    );
    // The issue is parked at the attempt bound (non-retryable), not left retryable.
    let row = state
        .get_issue(&id.to_string())
        .expect("get")
        .expect("row present");
    assert_eq!(
        row.phase_substate.as_deref(),
        Some(PhaseSubstate::AnswerUnreachable.as_str())
    );
    assert!(
        row.answer_attempts >= MAX_ANSWER_ATTEMPTS,
        "an invalid-slug failure must park at the bound so the sweep never retries it (got {})",
        row.answer_attempts
    );
    assert!(matches!(
        actions.as_slice(),
        [AnswerAction::Unreachable { .. }]
    ));

    // A blocker was posted for a human.
    let blockers = crosslink
        .list_comments(id)
        .expect("comments")
        .into_iter()
        .filter(|c| c.kind == "blocker")
        .count();
    assert_eq!(
        blockers, 1,
        "a delivery-failure blocker must stand for a human"
    );

    // A second sweep re-classifies it as bound-exhausted and still never delivers.
    let transport2 = FakeTransport::ok();
    let actions2 = deliver_pending(
        &state,
        &crosslink,
        &log,
        &transport2,
        "firmware",
        &socket_root,
        300,
        2_000_000,
    )
    .expect("second sweep");
    assert_eq!(transport2.call_count(), 0);
    assert!(matches!(
        actions2.as_slice(),
        [AnswerAction::RetrySkipped { .. }]
    ));
}

/// Review #3 — a crash between `record_success`'s `answer_sent` persist and its
/// `close_issue` leaves an answered inbound issue permanently OPEN. Recovery
/// reconciles it: an `answer_sent` terminal inbound issue that is still open has
/// its idempotent close completed, and a second recovery pass is a no-op.
#[test]
fn answer_sent_zombie_is_closed_by_recovery() {
    let fx = build_fixture();
    let (state, log) = open_state(&fx);
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");

    // The zombie: an answered inbound issue whose close never happened (crash) —
    // the crosslink issue is still OPEN, the state row already `answer_sent`.
    let id = create_inbound(&fx.root, "firmware", "uuid-zombie");
    upsert_terminal(&state, id, PhaseSubstate::AnswerSent);
    assert_eq!(
        crosslink.read_issue(id).expect("read").status,
        "open",
        "precondition: the answered issue is still open (the crash-window zombie)"
    );

    // Recovery completes the close.
    let actions = recover(&state, &log, &manager, Some(&crosslink)).expect("recover");
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, RecoveryAction::CompletedAnswerClose { issue_id } if issue_id == &id.to_string())),
        "recovery must reconcile the answered-but-open zombie: {actions:?}"
    );
    assert_eq!(
        crosslink.read_issue(id).expect("read").status,
        "closed",
        "the answered issue must be closed after recovery"
    );

    // Idempotent: a second pass finds it already closed and does nothing.
    let again = recover(&state, &log, &manager, Some(&crosslink)).expect("second recover");
    assert!(
        !again
            .iter()
            .any(|a| matches!(a, RecoveryAction::CompletedAnswerClose { .. })),
        "a second recovery pass must be a no-op on the already-closed issue: {again:?}"
    );
}
