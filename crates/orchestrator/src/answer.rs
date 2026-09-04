//! The crash-safe crossbridge **answer-back state machine** (spec §1.3/§1.4).
//!
//! When an `xb:inbound` issue — untrusted work a peer submitted (step 4) —
//! reaches a **terminal phase**, its worked result must be delivered back to the
//! originating peer as a single `SubmitAnswer`, so the peer is never left
//! waiting. This module owns that delivery: a small state machine tracked in the
//! `phase_substate` column, plus the sweep that drives it each tick.
//!
//! ```text
//!   answer_pending ──send SubmitAnswer──▶ answer_sent   (xb-status:answered courtesy; close issue)
//!         │
//!         └─connect fails / peer offline / wire error ──▶ answer_unreachable
//!                     │  (post a --kind blocker on the FIRST failure)
//!                     └─retry ≤ 1 per crossbridge_answer_retry_interval_s,
//!                        bounded by MAX_ANSWER_ATTEMPTS ──▶ … (else REMAINS
//!                        answer_unreachable, blocker standing, never spins)
//! ```
//!
//! # Authority is `state.db`, never the `xb-status:*` label (review B5)
//!
//! The single source of truth for where an inbound issue is in this machine is
//! its `state.db` `phase_substate` ([`PhaseSubstate::AnswerPending`] /
//! [`AnswerSent`](PhaseSubstate::AnswerSent) /
//! [`AnswerUnreachable`](PhaseSubstate::AnswerUnreachable)). The
//! `xb-status:answered` crosslink label is applied only as a **courtesy mirror**
//! on success — it is written incoherently by three crossbridge binaries and is
//! never read back to make a decision here. Every branch below reads `state.db`.
//!
//! # The terminal set is one definition ([`Phase::is_terminal`])
//!
//! Delivery fires when an inbound issue's phase is any of the terminal phases —
//! today `Merged`, `PrOpen`, `AwaitingHumanMerge`, `OrchestratorError`. That set
//! is enumerated in exactly one place, [`Phase::is_terminal`], which both this
//! module's [`phase_delivers_answer`] trigger and crash-recovery's `is_terminal`
//! delegate to — so the step-6 human gate (`awaiting-inbound-approval`) adds one
//! entry, in one place, and the answer machine and recovery can never disagree
//! about what "terminal" means.
//!
//! # Bounded, rate-limited, degraded retry
//!
//! [`AnswerUnreachable`](PhaseSubstate::AnswerUnreachable) is a **degraded but
//! non-terminal** waiting state, retried on ordinary poll ticks (not only on
//! restart). Two independent guards keep it from ever spinning:
//!
//! - **Rate limit:** at most one retry per `crossbridge_answer_retry_interval_s`
//!   ([`CrossbridgeConfig::answer_retry_interval`]). The clock is the issue row's
//!   `updated_at`, which the answer sweep is the *sole* writer of once the issue
//!   is terminal (see [`crate::state`] MIGRATION_V2).
//! - **Attempt bound:** after [`MAX_ANSWER_ATTEMPTS`] failures the issue
//!   **remains** `answer_unreachable` with its `--kind blocker` standing for a
//!   human — the sweep stops retrying it entirely. It never auto-resolves.
//!
//! # Crash-safety / idempotency (spec §1.4)
//!
//! Recovery keys off `phase_substate` ([`crate::recovery::plan_recovery`]): an
//! inbound issue in `answer_pending` or `answer_unreachable` is left in place for
//! the next tick's sweep to re-attempt; `answer_sent` is a completed answer whose
//! only outstanding work is the idempotent close, which recovery re-applies if a
//! crash landed between the `answer_sent` persist and the close (review #3).
//!
//! crossbridge does **source-side content dedup** keyed on the `source_uuid`
//! ([`AnswerReq::source_uuid`]), so a re-send after a crash between "peer
//! accepted" and "we recorded `answer_sent`" cannot double-answer — we rely on
//! that and keep **no** local sent-ledger. This is an **accepted external
//! dependency**: the dedup lives in crossbridge, not this crate, and cannot be
//! exercised by the sandbox's fake transport, so it is not covered by these tests
//! — if that upstream invariant ever weakens, a crash in the send window could
//! double-answer. It is documented here honestly rather than defended locally
//! (the-hater review #4); an integration test against the real crossbridge dedup
//! path is the follow-up before the 5-node deployment trusts it.
//!
//! **Down-time submits are not buffered.** While this node is down a peer's
//! `submit` fails fast ("peer not connected") and the peer retries; there is no
//! phantom inbound buffer to drain here, so none is built.
//!
//! # Trust boundary (review N1/N2)
//!
//! Gathering the `kind=result` comments and the `xb-source:`/`xb-ref:` labels is
//! done through [`CrosslinkRepo`] (the sole namer of crosslink types). **Only**
//! the `SubmitAnswer` wire round-trip crosses into `crossbridge_api`, behind the
//! [`AnswerTransport`] seam — so tests inject a fake and never touch a socket.

#![allow(clippy::result_large_err)]

use std::path::Path;

use serde_json::json;
use vetinari_crossbridge_api::labels::{
    XB_INBOUND, XB_REF_PREFIX, XB_SOURCE_PREFIX, XB_STATUS_ANSWERED,
};
use vetinari_crossbridge_api::{AnswerComment, AnswerOutcome, AnswerReq, CrossbridgeError};
use vetinari_crosslink_api::CrosslinkRepo;

use crate::artifacts::CommentKind;
use crate::events::{emit, EventLog};
use crate::pump::PumpError;
use crate::state::{EventKind, Phase, PhaseSubstate, StateDb};

/// The role attribution recorded on answer-back blocker comments (AC-16): a
/// delivery-failure blocker is posted by the orchestrator itself, on behalf of
/// the crossbridge answer path.
const ANSWER_ROLE_TAG: &str = "crossbridge";

/// The crosslink comment kind gathered and delivered to the source peer — the
/// worker's `--kind result` output (spec §1.3: only `kind=result` rides back).
const RESULT_COMMENT_KIND: CommentKind = CommentKind::Result;

/// Overall cap on failed `SubmitAnswer` attempts for one inbound issue. After
/// this many failures the issue **remains** `answer_unreachable` — its
/// `--kind blocker` stands for human attention and the sweep stops retrying it,
/// so a permanently-offline peer can never make the pump spin (spec §1.3
/// "bounded"). Not operator-tunable: it is a state-machine invariant. With the
/// default ~300s rate limit this is roughly an hour of courteous re-polling.
pub const MAX_ANSWER_ATTEMPTS: i64 = 12;

/// Maximum `SubmitAnswer` **delivery attempts** made in a single
/// [`deliver_pending`] sweep — the per-tick fan-out cap (review #1).
///
/// Each attempt is a blocking Unix-socket round-trip run serially on the pump's
/// single thread, bounded per call by crossbridge's ~10s read + ~10s write
/// socket timeout. The per-call timeout bounds *one* call; nothing else bounds
/// the *number* of calls, so without a cap a burst of N newly-terminal inbound
/// issues to silent peers would stall one `tick()` for N × ~20s — during which
/// the pump drives nothing, reaps no workers, and runs no stall detection.
///
/// Capping the fan-out bounds one tick's worst-case pump freeze to
/// `K × per-call-timeout` and spreads N due answers over ~N/K ticks. Remaining
/// due issues are simply picked up on later ticks; the pump ticks frequently and
/// pilot inbound volume is low, so a small K is correct. Rate-limited /
/// bound-exhausted *skips* are cheap and do NOT count against K — only issues
/// that actually reach the wire do.
pub const MAX_ANSWER_DELIVERIES_PER_TICK: usize = 2;

/// Maximum length of an `xb-source:` peer slug we will accept before using it to
/// build a filesystem socket path (review #2). crossbridge slugs derive from a
/// repo's origin-remote last path segment; a real one is far shorter than this
/// generous bound, which exists only to reject a pathological oversized label.
const MAX_PEER_SLUG_LEN: usize = 128;

/// A deterministic per-issue jitter, in `0..=retry_interval_s/4` seconds, added
/// to an `answer_unreachable` issue's retry due-time (review #1).
///
/// Answers that fail in the same tick share ~one `updated_at`, so without jitter
/// they all come due together exactly one interval later — a thundering herd that
/// batches an N × socket-timeout freeze into a single tick, repeating each retry
/// round. Offsetting each issue's due-time by a value derived from its id spreads
/// the herd across ticks. The derivation is pure arithmetic on the issue id — **no
/// RNG** (recovery replays the sweep, so the due-time must be deterministic). The
/// offset only ever *delays* a retry (it is added to the interval), so the
/// rate-limit invariant "at most one retry per interval" still holds — jitter can
/// only make a retry later, never sooner.
fn retry_jitter_s(issue_id: i64, retry_interval_s: i64) -> i64 {
    let span = retry_interval_s / 4;
    if span <= 0 {
        return 0;
    }
    // Unsigned modulo on the id's magnitude: deterministic, total, no RNG.
    (issue_id.unsigned_abs() % span as u64) as i64
}

/// Whether an `xb-source:` peer slug is a valid crossbridge slug safe to
/// interpolate into a socket path (review #2).
///
/// The slug arrives on a **peer-controlled** `xb-source:` label (this is an
/// `xb:inbound`, untrusted issue) and would be interpolated into
/// `socket_root/own_slug/<slug>.socket`. Without a whitelist, a slug containing
/// `/` or a `..` segment would traverse out of the socket directory. crossbridge
/// derives slugs from an origin-remote path segment, which in practice is
/// `[A-Za-z0-9._-]`; we enforce exactly that shape as a hard whitelist on the
/// trust boundary: non-empty, bounded length, no path separators, and never the
/// `.`/`..` traversal segments. A slug that fails this is treated as a permanent,
/// non-retryable delivery failure ([`record_invalid_slug`]) — the path is never
/// built and no delivery is attempted.
fn is_valid_peer_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= MAX_PEER_SLUG_LEN
        && slug != "."
        && slug != ".."
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether an issue's terminal `phase` triggers answer-back delivery (spec
/// §1.3): a terminal inbound issue is exactly one whose worked result must be
/// answered back to the source peer.
///
/// The terminal set is defined **once**, on [`Phase::is_terminal`] — the single
/// source of truth this trigger and crash-recovery's `is_terminal` both read, so
/// the two never drift. A peer must get an answer whether its work merged, opened
/// a PR, parked for a human merge, or faulted, so it is never silently dropped.
/// **Step 6** extends the terminal set on [`Phase::is_terminal`], in that one
/// place.
pub fn phase_delivers_answer(phase: Phase) -> bool {
    phase.is_terminal()
}

/// Whether an issue's crosslink label set marks it as `xb:inbound` — untrusted,
/// peer-submitted work (step 4). Only inbound issues are answered; a
/// locally-authored issue is never touched by this machine.
pub fn is_inbound(labels: &[String]) -> bool {
    labels.iter().any(|l| l == XB_INBOUND)
}

/// The value carried after `prefix` in the first matching `xb-*:<value>` label,
/// e.g. the peer slug from `xb-source:firmware` or the correlation id from
/// `xb-ref:abc-123`.
fn label_value<'a>(labels: &'a [String], prefix: &str) -> Option<&'a str> {
    labels.iter().find_map(|l| l.strip_prefix(prefix))
}

/// The seam through which a `SubmitAnswer` reaches the source peer.
///
/// Production wraps [`vetinari_crossbridge_api::answer`] ([`CrossbridgeTransport`]);
/// tests inject a fake that returns a scripted success / `PeerUnreachable` / wire
/// error and records every [`AnswerReq`] it was handed — the sandbox has no
/// crossbridge peer or supervisor, so all answer-machine tests use the fake.
/// Mirrors landing's `PrOpener` seam.
pub trait AnswerTransport {
    /// Deliver one answer round-trip. A connect/stall/wire failure is returned as
    /// the typed [`CrossbridgeError`]; the sweep classifies it into the
    /// `answer_unreachable` degraded state (it is never `?`-propagated).
    fn answer(&self, req: &AnswerReq) -> std::result::Result<AnswerOutcome, CrossbridgeError>;
}

/// Production [`AnswerTransport`]: one real `SubmitAnswer` wire round-trip.
pub struct CrossbridgeTransport;

impl AnswerTransport for CrossbridgeTransport {
    fn answer(&self, req: &AnswerReq) -> std::result::Result<AnswerOutcome, CrossbridgeError> {
        vetinari_crossbridge_api::answer(req.clone())
    }
}

/// One reconciliation the answer sweep performed on an inbound issue, for the
/// caller's log and the tests to assert against.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnswerAction {
    /// The `SubmitAnswer` succeeded: substate → `answer_sent`, the
    /// `xb-status:answered` courtesy label applied, and the issue closed.
    Answered {
        /// The inbound issue answered.
        issue_id: i64,
    },
    /// Delivery failed: substate → `answer_unreachable` (a `--kind blocker` was
    /// posted on the first such failure). Retried, bounded, on a later tick.
    Unreachable {
        /// The inbound issue whose answer failed.
        issue_id: i64,
        /// The new failed-attempt count after this failure.
        attempts: i64,
    },
    /// An `answer_unreachable` issue was skipped this tick without a delivery
    /// attempt — either rate-limited or the attempt bound is exhausted.
    RetrySkipped {
        /// The inbound issue skipped.
        issue_id: i64,
        /// Why it was skipped.
        reason: SkipReason,
    },
}

/// Why the sweep skipped an `answer_unreachable` issue without re-attempting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Less than `crossbridge_answer_retry_interval_s` has elapsed since the last
    /// attempt — the per-interval rate limit.
    RateLimited,
    /// The issue has hit [`MAX_ANSWER_ATTEMPTS`]; it stays `answer_unreachable`
    /// with its blocker standing for a human, and is retried no further.
    BoundExhausted,
}

/// **Trigger** — mark a just-terminated inbound issue `answer_pending` so the
/// sweep will deliver its result (spec §1.3).
///
/// Called by the pump the moment it commits a terminal transition for an issue.
/// It is a no-op (`Ok(false)`) for every issue that must stay unchanged:
///
/// - a non-terminal phase (guarded by [`phase_delivers_answer`] against the
///   `state.db` phase — the authority, not the caller's outcome enum);
/// - a **non-inbound** (locally-authored) issue — the crosslink labels are read
///   here so the pump's own path is undisturbed;
/// - an issue already in an answer substate (idempotent — a re-trigger must not
///   reset `answer_sent`/`answer_unreachable` back to `answer_pending`).
///
/// Only when all three pass does it write `phase_substate = answer_pending`,
/// leaving the terminal `phase` intact ([`StateDb::set_phase_substate`]).
pub fn on_issue_terminal(
    state: &StateDb,
    crosslink: &CrosslinkRepo,
    log: &EventLog,
    issue_id: i64,
) -> Result<bool, PumpError> {
    let key = issue_id.to_string();
    let Some(row) = state.get_issue(&key)? else {
        return Ok(false);
    };
    // Authority is state.db: only a genuinely terminal inbound issue is armed.
    if !phase_delivers_answer(row.phase) {
        return Ok(false);
    }
    // Already in the answer machine — don't reset it (idempotent re-trigger).
    // This is the "first terminal wins" guard: once an inbound issue has been
    // armed/answered, a re-trigger on the SAME terminal phase must not reset
    // `answer_sent`/`answer_unreachable` back to `answer_pending`.
    //
    // NOTE (step 6 / REQ-SWARM-1): this guard alone does NOT cover the
    // `park → approve → merge` sequence, because landing clears `phase_substate`
    // to `None` on the merge (the SECOND terminal), which would slip past this
    // check. That double-answer is prevented structurally at the caller: the
    // pump's inbound-approval resume sweep ([`crate::pump::BuildPump::resume_approved_inbound`])
    // deliberately does NOT call this trigger after landing an approved inbound
    // issue, so the peer is answered exactly once, at the park.
    if let Some(sub) = row
        .phase_substate
        .as_deref()
        .and_then(PhaseSubstate::from_db_str)
    {
        if is_answer_substate(sub) {
            return Ok(false);
        }
    }
    // Only inbound (untrusted, peer-submitted) work gets an answer.
    let info = crosslink.read_issue(issue_id)?;
    if !is_inbound(&info.labels) {
        return Ok(false);
    }

    state.set_phase_substate(&key, Some(PhaseSubstate::AnswerPending))?;
    emit(
        state,
        log,
        EventKind::Transition,
        Some(&key),
        None,
        &json!({
            "answer": "pending",
            "phase": row.phase.as_str(),
            "reason": "inbound issue reached a terminal phase — answer queued",
        }),
    )?;
    Ok(true)
}

/// Whether a substate belongs to the answer-back machine.
fn is_answer_substate(sub: PhaseSubstate) -> bool {
    matches!(
        sub,
        PhaseSubstate::AnswerPending | PhaseSubstate::AnswerSent | PhaseSubstate::AnswerUnreachable
    )
}

/// **Sweep** — deliver every inbound issue awaiting an answer (spec §1.3).
///
/// Run once per pump tick, after the drive step. For every issue whose
/// `state.db` substate is `answer_pending` or `answer_unreachable`:
///
/// - `answer_pending` is always attempted (its first delivery).
/// - `answer_unreachable` is attempted only if it is **past** the rate-limit
///   interval plus a deterministic per-issue jitter
///   (`now - updated_at >= retry_interval_s + retry_jitter_s(id)`) **and** under
///   [`MAX_ANSWER_ATTEMPTS`]; otherwise it is skipped this tick. The jitter
///   ([`retry_jitter_s`]) disperses a herd of answers that all failed in the same
///   tick so they don't all come due together (review #1).
///
/// An attempt gathers the `kind=result` comments and the `xb-source:`/`xb-ref:`
/// labels via `crosslink`, builds an [`AnswerReq`], and delivers it through
/// `transport`. Success → `answer_sent` + `xb-status:answered` + close. Any
/// failure → `answer_unreachable` (a `--kind blocker` on the first failure),
/// bounded and rate-limited.
///
/// # Bounded fan-out (review #1)
///
/// At most [`MAX_ANSWER_DELIVERIES_PER_TICK`] issues actually reach the wire per
/// sweep. Because each attempt blocks the single pump thread for up to
/// crossbridge's socket timeout, an unbounded fan-out would let a burst of due
/// answers to silent peers freeze the whole pump. Once the cap is hit the sweep
/// stops attempting and the remaining due issues wait for the next tick. Cheap
/// skips (rate-limited / bound-exhausted) don't count against the cap.
///
/// # Per-issue error isolation (review #5)
///
/// A crosslink/state fault while handling **one** issue (a transient `read_issue`
/// hiccup, say) is logged and skipped, not `?`-propagated — so it can't deny
/// delivery to the rest of this tick's due issues or wedge the whole sweep.
///
/// `now` is unix seconds (injected so tests are deterministic); production
/// passes the wall clock. Returns the per-issue [`AnswerAction`]s taken.
#[allow(clippy::too_many_arguments)]
pub fn deliver_pending(
    state: &StateDb,
    crosslink: &CrosslinkRepo,
    log: &EventLog,
    transport: &dyn AnswerTransport,
    own_slug: &str,
    socket_root: &Path,
    retry_interval_s: i64,
    now: i64,
) -> Result<Vec<AnswerAction>, PumpError> {
    let mut actions = Vec::new();
    // Count only issues that reach the wire; the cap bounds the per-tick fan-out
    // so a burst of blocking round-trips can't freeze the pump (review #1).
    let mut deliveries = 0usize;
    for row in state.list_issues()? {
        if deliveries >= MAX_ANSWER_DELIVERIES_PER_TICK {
            // Fan-out cap hit: leave the remaining due issues for the next tick.
            break;
        }
        let Some(sub) = row
            .phase_substate
            .as_deref()
            .and_then(PhaseSubstate::from_db_str)
        else {
            continue;
        };
        // Only the two waiting substates are swept; answer_sent is done (its
        // crash-window close is reconciled by recovery, not the sweep — review #3).
        let pending = match sub {
            PhaseSubstate::AnswerPending => true,
            PhaseSubstate::AnswerUnreachable => false,
            _ => continue,
        };
        let Ok(issue_id) = row.issue_id.parse::<i64>() else {
            continue;
        };

        if !pending {
            // Degraded retry guards (bound first, then rate limit + jitter).
            if row.answer_attempts >= MAX_ANSWER_ATTEMPTS {
                actions.push(AnswerAction::RetrySkipped {
                    issue_id,
                    reason: SkipReason::BoundExhausted,
                });
                continue;
            }
            // Add a deterministic per-issue jitter so a herd of same-tick failures
            // doesn't all come due in the same later tick (review #1).
            let due_after =
                retry_interval_s.saturating_add(retry_jitter_s(issue_id, retry_interval_s));
            if now.saturating_sub(row.updated_at) < due_after {
                actions.push(AnswerAction::RetrySkipped {
                    issue_id,
                    reason: SkipReason::RateLimited,
                });
                continue;
            }
        }

        // Per-issue isolation (review #5): a crosslink/state fault on ONE issue is
        // logged and skipped, never `?`-propagated to abort the rest of the sweep.
        match attempt_delivery(
            state,
            crosslink,
            log,
            transport,
            own_slug,
            socket_root,
            issue_id,
            sub,
        ) {
            Ok(action) => {
                actions.push(action);
                deliveries += 1;
            }
            Err(err) => {
                emit(
                    state,
                    log,
                    EventKind::Transition,
                    Some(&row.issue_id),
                    None,
                    &json!({
                        "answer": "sweep_error",
                        "reason": "per-issue delivery attempt errored — skipped this tick",
                        "detail": err.to_string(),
                    }),
                )?;
            }
        }
    }
    Ok(actions)
}

/// Gather the answer inputs, deliver one round-trip, and transition the issue.
#[allow(clippy::too_many_arguments)]
fn attempt_delivery(
    state: &StateDb,
    crosslink: &CrosslinkRepo,
    log: &EventLog,
    transport: &dyn AnswerTransport,
    own_slug: &str,
    socket_root: &Path,
    issue_id: i64,
    from_substate: PhaseSubstate,
) -> Result<AnswerAction, PumpError> {
    // Route inputs through crosslink_api (review N2): labels for peer_slug /
    // source_uuid, comments for the kind=result payload.
    let info = crosslink.read_issue(issue_id)?;
    let peer_slug = label_value(&info.labels, XB_SOURCE_PREFIX);
    let source_uuid = label_value(&info.labels, XB_REF_PREFIX);
    let (Some(peer_slug), Some(source_uuid)) = (peer_slug, source_uuid) else {
        // A malformed inbound issue (missing routing labels) can never be
        // answered. Treat it as a bounded delivery failure so a human sees the
        // blocker rather than the pump silently dropping it.
        return record_failure(
            state,
            crosslink,
            log,
            issue_id,
            from_substate,
            "unknown",
            "inbound issue is missing its xb-source:/xb-ref: labels — cannot route the answer",
        );
    };

    // Validate the peer slug BEFORE it is used to build a socket path (review #2):
    // it rides an untrusted `xb-source:` label, and an invalid one (a `/` or `..`)
    // would traverse out of `socket_root`. A malformed slug can never be routed, so
    // this parks the issue permanently rather than retrying a doomed delivery — the
    // socket path is never even formed. (`source_uuid` only rides the wire payload,
    // never a path, and is bounded by crossbridge's frame-size cap.)
    if !is_valid_peer_slug(peer_slug) {
        return record_invalid_slug(state, crosslink, log, issue_id, from_substate, peer_slug);
    }

    let comments: Vec<AnswerComment> = crosslink
        .list_comments(issue_id)?
        .into_iter()
        .filter(|c| c.kind == RESULT_COMMENT_KIND.as_str())
        .map(|c| AnswerComment {
            kind: c.kind,
            content: c.body,
        })
        .collect();

    let req = AnswerReq {
        peer_slug: peer_slug.to_owned(),
        own_slug: own_slug.to_owned(),
        socket_root: socket_root.to_path_buf(),
        source_uuid: source_uuid.to_owned(),
        comments,
    };

    match transport.answer(&req) {
        Ok(outcome) => record_success(state, crosslink, log, issue_id, &req, &outcome),
        Err(err) => record_failure(
            state,
            crosslink,
            log,
            issue_id,
            from_substate,
            peer_slug,
            &err.to_string(),
        ),
    }
}

/// Success: substate → `answer_sent`, apply the `xb-status:answered` courtesy
/// label, close the issue, emit. Authority is the substate write; the label and
/// close are the courtesy mirror + lifecycle end (spec §1.3).
fn record_success(
    state: &StateDb,
    crosslink: &CrosslinkRepo,
    log: &EventLog,
    issue_id: i64,
    req: &AnswerReq,
    outcome: &AnswerOutcome,
) -> Result<AnswerAction, PumpError> {
    let key = issue_id.to_string();
    // state.db is the authority — write it FIRST so a crash before the courtesy
    // label/close still leaves the machine terminal (answer_sent), and recovery
    // no-ops it. crossbridge source-side dedup makes even a stray re-send safe.
    state.set_phase_substate(&key, Some(PhaseSubstate::AnswerSent))?;
    // Courtesy mirror + close (idempotent: label_add no-ops if present,
    // close_issue no-ops if already closed).
    crosslink.label_add(issue_id, XB_STATUS_ANSWERED)?;
    crosslink.close_issue(issue_id)?;
    emit(
        state,
        log,
        EventKind::Transition,
        Some(&key),
        None,
        &json!({
            "answer": "sent",
            "peer": req.peer_slug,
            "source_uuid": req.source_uuid,
            "comments": req.comments.len(),
            "remote_issue_id": outcome.remote_issue_id,
        }),
    )?;
    Ok(AnswerAction::Answered { issue_id })
}

/// Failure: substate → `answer_unreachable`, bump `answer_attempts`, and post a
/// `--kind blocker` on the **first** failure (the transition out of
/// `answer_pending`). Bounded/rate-limited retry is the sweep's job; this only
/// records the degraded state.
fn record_failure(
    state: &StateDb,
    crosslink: &CrosslinkRepo,
    log: &EventLog,
    issue_id: i64,
    from_substate: PhaseSubstate,
    peer_slug: &str,
    detail: &str,
) -> Result<AnswerAction, PumpError> {
    let key = issue_id.to_string();
    let first_failure = from_substate == PhaseSubstate::AnswerPending;
    let attempts = state.record_answer_unreachable(&key)?;
    if first_failure {
        let body = format!(
            "Answer-back to peer `{peer_slug}` failed: {detail}.\n\n\
             The worked result is delivered on a later tick once the peer is reachable \
             (retried at most once per `crossbridge_answer_retry_interval_s`, up to \
             {MAX_ANSWER_ATTEMPTS} attempts). This blocker stands for human attention until \
             the peer answers or a human intervenes."
        );
        crosslink.comment_write(
            issue_id,
            CommentKind::Blocker.as_str(),
            &body,
            Some(ANSWER_ROLE_TAG),
        )?;
    }
    emit(
        state,
        log,
        EventKind::Transition,
        Some(&key),
        None,
        &json!({
            "answer": "unreachable",
            "peer": peer_slug,
            "attempts": attempts,
            "first_failure": first_failure,
            "detail": detail,
        }),
    )?;
    Ok(AnswerAction::Unreachable { issue_id, attempts })
}

/// Permanent, non-retryable delivery failure: the inbound issue's `xb-source:`
/// slug is not a valid crossbridge slug, so no socket path can be formed and no
/// retry can ever fix it (review #2). Park the answer at the attempt bound (so the
/// sweep stops retrying it) and, on the first such failure, post a `--kind
/// blocker` for a human. Distinct from [`record_failure`]'s *retryable*
/// `answer_unreachable` (a transient peer outage).
///
/// The raw, untrusted slug is deliberately NOT reflected into the markdown blocker
/// body (it goes only into the structured event log, which escapes it); the
/// blocker states the rule instead.
fn record_invalid_slug(
    state: &StateDb,
    crosslink: &CrosslinkRepo,
    log: &EventLog,
    issue_id: i64,
    from_substate: PhaseSubstate,
    peer_slug: &str,
) -> Result<AnswerAction, PumpError> {
    let key = issue_id.to_string();
    let first_failure = from_substate == PhaseSubstate::AnswerPending;
    // Retire it: force the attempt count to the bound so the sweep never retries.
    let attempts = state.retire_answer_unreachable(&key, MAX_ANSWER_ATTEMPTS)?;
    if first_failure {
        let body = format!(
            "Answer-back cannot be routed: the inbound issue's `xb-source:` peer slug is not a \
             valid crossbridge slug (must be non-empty, at most {MAX_PEER_SLUG_LEN} chars of \
             `[A-Za-z0-9._-]`, with no path separators or `..`). No socket path can be formed, \
             so the worked result cannot be delivered and this will NOT be retried — a human \
             must correct the source routing. (Reported by the crossbridge answer path.)"
        );
        crosslink.comment_write(
            issue_id,
            CommentKind::Blocker.as_str(),
            &body,
            Some(ANSWER_ROLE_TAG),
        )?;
    }
    emit(
        state,
        log,
        EventKind::Transition,
        Some(&key),
        None,
        &json!({
            "answer": "invalid_slug",
            "peer_slug": peer_slug,
            "attempts": attempts,
            "first_failure": first_failure,
            "reason": "xb-source: slug is not a valid crossbridge slug — parked, not retried",
        }),
    )?;
    Ok(AnswerAction::Unreachable { issue_id, attempts })
}

// ============================================================================
// Tests (pure helpers only; the behavioral trigger/sweep tests, which need a
// real crosslink repo + a fake transport, live in tests/answer_back.rs)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_set_covers_every_terminal_phase_and_no_drivable_one() {
        // The delivery trigger fires on EVERY terminal phase (a peer never hangs)
        // and on NO drivable/in-flight one.
        for phase in [
            Phase::Merged,
            Phase::PrOpen,
            Phase::AwaitingHumanMerge,
            Phase::OrchestratorError,
        ] {
            assert!(
                phase_delivers_answer(phase),
                "{phase} is terminal — it must trigger answer delivery"
            );
        }
        for phase in [
            Phase::Graphed,
            Phase::Implementing,
            Phase::QaGate,
            Phase::AdversaryReview,
            Phase::Converged,
            Phase::Landing,
        ] {
            assert!(
                !phase_delivers_answer(phase),
                "{phase} is not terminal — it must NOT trigger answer delivery"
            );
        }
    }

    #[test]
    fn is_inbound_reads_the_marker_label() {
        assert!(is_inbound(&[
            "phase:merged".to_owned(),
            XB_INBOUND.to_owned()
        ]));
        assert!(!is_inbound(&["phase:merged".to_owned()]));
        assert!(!is_inbound(&[]));
    }

    #[test]
    fn valid_peer_slug_accepts_real_slugs_and_rejects_traversal() {
        // Real crossbridge slugs pass.
        for good in [
            "firmware",
            "reversing-node-2",
            "a.b_c-1",
            "x",
            &"a".repeat(128),
        ] {
            assert!(is_valid_peer_slug(good), "`{good}` is a valid slug");
        }
        // Path-traversal and separator slugs are rejected — these are exactly the
        // ones that would escape `socket_root` if interpolated into a path.
        for bad in [
            "",
            ".",
            "..",
            "../../etc/x",
            "a/b",
            "/abs",
            "peer/../../root",
            "with space",
            "tab\tx",
            "new\nline",
            "nul\0byte",
            &"a".repeat(129),
        ] {
            assert!(!is_valid_peer_slug(bad), "`{bad}` must be rejected");
        }
    }

    #[test]
    fn invalid_slug_never_forms_a_path_outside_socket_root() {
        // Defense-in-depth check that the guard fires for the canonical traversal
        // slug BEFORE any `AnswerReq` (and thus any socket path) is built.
        let traversal = "../../etc/x";
        assert!(
            !is_valid_peer_slug(traversal),
            "the traversal slug must be rejected so `socket_root/own/<slug>.socket` is never formed"
        );
    }

    #[test]
    fn retry_jitter_is_deterministic_and_bounded_to_a_quarter_interval() {
        let interval = 300;
        let span = interval / 4; // 75
        for id in [0i64, 1, 2, 7, 42, 12_345, i64::MAX, i64::MIN] {
            let j = retry_jitter_s(id, interval);
            assert!(
                (0..span).contains(&j),
                "jitter {j} for id {id} out of 0..{span}"
            );
            // Deterministic: same inputs, same output (recovery replays the sweep).
            assert_eq!(j, retry_jitter_s(id, interval), "jitter must be pure");
        }
        // Different ids disperse to different offsets (herd-breaking).
        assert_ne!(retry_jitter_s(1, interval), retry_jitter_s(2, interval));
        // A tiny/zero interval yields no jitter rather than a divide-by-zero.
        assert_eq!(retry_jitter_s(9, 0), 0);
        assert_eq!(retry_jitter_s(9, 3), 0);
    }

    #[test]
    fn per_tick_delivery_cap_is_small() {
        // The fan-out cap must stay small so one tick's worst-case pump freeze is
        // K × the socket timeout, not N × it (review #1).
        assert!(
            (1..=4).contains(&MAX_ANSWER_DELIVERIES_PER_TICK),
            "the per-tick delivery cap must be small"
        );
    }

    #[test]
    fn label_value_extracts_the_prefixed_payload() {
        let labels = vec![
            "xb:inbound".to_owned(),
            "xb-source:firmware".to_owned(),
            "xb-ref:abc-123".to_owned(),
            "phase:merged".to_owned(),
        ];
        assert_eq!(label_value(&labels, XB_SOURCE_PREFIX), Some("firmware"));
        assert_eq!(label_value(&labels, XB_REF_PREFIX), Some("abc-123"));
        assert_eq!(label_value(&labels, "xb-nope:"), None);
    }
}
