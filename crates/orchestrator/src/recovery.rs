//! REQ-15 deterministic crash-recovery table (AC-17, AC-18).
//!
//! On restart the orchestrator must, for every issue in a non-terminal phase,
//! re-derive ground truth from the filesystem (`_orchestrator/DONE`, the jj
//! commit graph, the `main` bookmark position) and deterministically **advance,
//! repeat, or roll back** the phase — idempotently, so running recovery twice
//! yields the same final state.
//!
//! This module owns two halves:
//!
//! - [`plan_recovery`] — the pure decision table: `(phase, substate)` +
//!   ground-truth flags ⇒ a typed [`RecoveryPlan`]. It is **total** over every
//!   `Phase`×`PhaseSubstate` combination; an unknown/inconsistent combo yields a
//!   conservative [`RecoveryError`] rather than a silent mis-recovery.
//! - [`recover`] — the executor: it iterates `state.db` (every non-terminal
//!   issue, every `active_workers` row, plus terminal `xb:inbound` issues still
//!   carrying an answer substate — review #3), reads the ground truth each plan
//!   needs, and applies the plan through the same primitives the pump uses
//!   ([`WorkspaceManager`] for `.jj/`, [`landing::resume_from`] for landing
//!   substates, the `posted_artifacts` ledger for translation). A per-issue
//!   failure is **quarantined**, not fatal: the offending issue is parked at
//!   `phase:orchestrator-error` and the pass continues with the others, so one
//!   poison issue can never refuse startup for the whole node.
//!
//! # The recovery table
//!
//! For each non-terminal issue and its `active_workers` row (if any), classified
//! by `(phase, substate)` and filesystem ground truth:
//!
//! | phase / substate                              | ground truth checked            | action |
//! |-----------------------------------------------|---------------------------------|--------|
//! | `graphed` (none)                              | —                               | leave it (the pump drives a fresh graphed issue) |
//! | `implementing` (none), **no `DONE`**          | `_orchestrator/DONE` absent     | crash mid-work: kill survivor (best-effort), `forget`+`rm -rf` the workspace, drop the worker row, roll to `implementing` (drivable → the pump re-drives fresh, REQ-8) |
//! | `implementing` (none), **`DONE` present**     | `_orchestrator/DONE` present    | worker finished, orchestrator crashed pre-advance: re-run the **idempotent** translation, deduped against the **content-addressed, issue-scoped** ledger (AC-17: each comment posts at most once, whichever attempt/uuid produced it), then clean the workspace, drop the worker row, roll to `implementing` so the pump re-drives to QA→land. Because the ledger key is `(issue_id, artifact_path, content_sha, finding_index)` — NOT the uuid — the subsequent pump re-drive under a fresh uuid re-translates the identical content as a dedup no-op, so nothing double-posts |
//! | `qa-gate` (any / `qa_running` / `qa_passed_pending_transition`) | (QA is re-runnable) | QA is not crash-fragile — clean the workspace, drop the worker row, roll to `implementing` so the pump re-runs implement→QA |
//! | `landing` (`rebase_started` / `rebase_done_bookmark_pending` / `bookmark_moved_complete`) | jj graph + `main` position | **delegate** to [`landing::resume_from`] with the persisted substate; it reads the bookmark ground truth and completes or no-ops idempotently (AC-18) |
//! | `converged` (none)                            | —                               | about-to-land but never entered landing: re-derive the change and run [`landing::land_local`] from the top (idempotent) |
//! | `adversary-review` (none)                     | —                               | iteration-2+ phase not driven by the MVP pump — conservatively roll to `implementing` so the pump re-drives |
//! | any phase + a `landing` substate that doesn't match the phase, or a worker phase with a `landing`/`qa` substate that can't be reconciled | —                       | [`RecoveryError::StateDbInconsistent`] → the issue is **quarantined** to `phase:orchestrator-error` and the pass continues with the others |
//! | terminal phase + `answer_pending` / `answer_unreachable` (an `xb:inbound` issue mid answer-back, spec §1.3) | — | **re-attempt**: leave the substate in place (NoAction) so the pump's answer sweep re-delivers next tick; crossbridge source-side dedup makes the re-send safe |
//! | terminal phase + `answer_sent` (answer already delivered) | crosslink issue status | **complete the close**: if the answered issue is still open (a crash landed between the `answer_sent` persist and `close_issue`, review #3), re-apply the `xb-status:answered` label and close it — idempotent, a no-op once closed |
//! | `merged` / `pr-open` / `awaiting-human-merge` / `orchestrator-error` (terminal, no answer substate) | — | no action |
//!
//! Unknown/newer `phase_substate` tokens (a database written by a newer binary)
//! are rejected up front with [`RecoveryError::UnknownSubstate`].
//!
//! # Idempotence
//!
//! Every action leaves the issue in a state a second `recover` pass finds
//! nothing to do for: a rolled-back issue has no `DONE` (workspace gone) and no
//! worker row, so the second pass re-classifies it as "graphed/implementing,
//! clean" and leaves it for the pump; a landing resume is itself idempotent
//! (the bookmark move is a jj no-op once `main` is at the target). [`recover`]
//! run twice therefore produces the same final state — asserted in the tests.
//!
//! # No shell-out (AC-24), no panics
//!
//! All `.jj/` work goes through [`WorkspaceManager`]; all filesystem work is
//! [`std::fs`]; crosslink is reached only through [`CrosslinkRepo`]. There is no
//! `unwrap`/`panic` on any non-test path.

#![allow(clippy::result_large_err)]

use serde_json::json;
use vetinari_crossbridge_api::labels::XB_STATUS_ANSWERED;
use vetinari_crosslink_api::CrosslinkRepo;
use vetinari_error::RecoveryError;

use crate::artifacts::{ArtifactSet, DoneSentinel};
use crate::events::{emit, EventLog};
use crate::landing::{
    self, branch_name, land_local, OctocrabPrOpener, PrOpener, RemoteLanding, MAIN_BOOKMARK,
};
use crate::state::{ActiveWorkerRow, EventKind, Phase, PhaseSubstate, PostedArtifact, StateDb};
use crate::workspace::{WorkspaceManager, WorkspaceName};

/// The role attribution recorded on translated crosslink comments (AC-16),
/// matching the build pump's `WORKER_ROLE_TAG` so a comment posted by recovery
/// is indistinguishable from one the pump would have posted.
const WORKER_ROLE_TAG: &str = "implementer";

/// The recovery action decided for an issue found mid-phase on restart.
///
/// A closed, typed set (no stringly phases): each variant names exactly what
/// [`recover`] does to reconcile the issue. [`plan_recovery`] returns one of
/// these for every recognized `(phase, substate)`; [`recover`] executes it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryPlan {
    /// The issue is already in a state the pump can drive (or a terminal one) —
    /// recovery leaves it untouched. Covers `graphed` and every terminal phase.
    NoAction,

    /// A worker phase (`implementing`/`qa-gate`) whose workspace has **no**
    /// `DONE`: the worker crashed mid-work. Kill any survivor (best-effort),
    /// `forget`+`rm -rf` the workspace, drop the `active_workers` row, and roll
    /// the issue back to `implementing` so the pump re-drives it fresh (REQ-8).
    CleanCrashedWorker,

    /// A worker phase (`implementing`) whose workspace **has** a valid `DONE`:
    /// the worker finished but the orchestrator crashed before advancing. Re-run
    /// the idempotent translation, deduped against the content-addressed,
    /// issue-scoped ledger (AC-17: at most once regardless of attempt/uuid),
    /// then clean the workspace, drop the row, and roll back to `implementing`
    /// so the pump re-drives to QA→land.
    ReplayDoneThenRedrive,

    /// A local `landing` substate: delegate to [`landing::resume_from`] with the
    /// persisted substate, which reads bookmark ground truth and completes or
    /// no-ops idempotently (AC-18). For the `Merging` substate (a crash during
    /// Merger resolution, REQ-19) [`recover`] first reaps the in-flight Merger
    /// `active_workers` row and forgets its workspace, then lets `resume_from`
    /// park the issue for a human — so neither the row nor the workspace dir leaks
    /// (F1).
    ResumeLanding {
        /// The landing substate to resume from.
        substate: PhaseSubstate,
    },

    /// A remote-mode `landing` substate (`push_started` / `push_done_pr_pending`
    /// / `pr_created`): delegate to [`landing::resume_remote_from`] with the
    /// persisted substate, reconstructing the [`RemoteLanding`] inputs + PR
    /// opener the same way the pump's `land_remote_mode` does. The push is
    /// idempotent (re-point + re-push) and PR creation is idempotent (an existing
    /// open PR is adopted, never re-created — F1/F2), so a crash mid remote
    /// landing RESUMES deterministically instead of quarantining and orphaning
    /// the pushed branch.
    ResumeRemoteLanding {
        /// The remote-landing substate to resume from.
        substate: PhaseSubstate,
    },

    /// `converged`: the issue is about to land but never entered a landing
    /// substate. Re-derive the change and run [`landing::land_local`] from the
    /// top of the (idempotent) landing machine.
    StartLanding,

    /// An `xb:inbound` issue at a terminal phase with substate `answer_sent` that
    /// may still be **open**: a crash landed between `record_success`'s
    /// `answer_sent` persist and its idempotent courtesy-label + `close_issue`
    /// (review #3). Re-apply the `xb-status:answered` label and close, both
    /// idempotently, so the answered issue can't dangle open forever. A no-op if
    /// the close already happened (a second recovery pass finds it closed).
    CompleteAnswerClose,
}

/// A single reconciliation [`recover`] applied to one issue, for the caller's
/// log and for the tests to assert against.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryAction {
    /// A crashed worker's workspace + row were cleaned and the issue rolled back
    /// to `implementing`.
    CleanedCrashedWorker {
        /// The issue reconciled.
        issue_id: String,
    },
    /// A finished worker's artifacts were (idempotently) re-translated and the
    /// issue rolled back to `implementing` for a fresh re-drive.
    ReplayedDone {
        /// The issue reconciled.
        issue_id: String,
        /// How many comments the ledger let through this pass (0 on a no-op
        /// replay — the AC-17 idempotency signal).
        posted: usize,
    },
    /// A landing substate was resumed via [`landing::resume_from`].
    ResumedLanding {
        /// The issue reconciled.
        issue_id: String,
        /// The terminal outcome the landing machine reached.
        outcome: landing::LandingOutcome,
    },
    /// A `converged` issue was landed from the top of the landing machine.
    StartedLanding {
        /// The issue reconciled.
        issue_id: String,
        /// The terminal outcome the landing machine reached.
        outcome: landing::LandingOutcome,
    },
    /// A crash-window zombie was reconciled: an answered (`answer_sent`) inbound
    /// issue that was still open had its idempotent close completed (review #3).
    /// Only emitted when the close actually did something (the issue was open); a
    /// second recovery pass finds it closed and produces nothing (idempotent).
    CompletedAnswerClose {
        /// The answered issue whose close was completed.
        issue_id: String,
    },
    /// Recovering this issue failed (a state.db inconsistency, an unknown
    /// substate, a jj-op failure resuming its landing, …). Rather than refuse
    /// startup for the whole node, the issue was **quarantined**: parked at
    /// `phase:orchestrator-error` (undrivable) so the pump skips it, and the
    /// pass continued with the other issues.
    Quarantined {
        /// The issue that could not be recovered.
        issue_id: String,
        /// The recovery error that led to the quarantine, rendered for the log.
        reason: String,
    },
}

/// Whether an issue is in a terminal phase recovery must never advance.
///
/// Delegates to [`Phase::is_terminal`] — the **single** terminal-set definition
/// the answer-back trigger ([`crate::answer::phase_delivers_answer`]) also reads,
/// so recovery and the answer machine can never disagree about "terminal" (and
/// step 6 extends the set in exactly one place, on `Phase::is_terminal`).
fn is_terminal(phase: Phase) -> bool {
    phase.is_terminal()
}

/// Whether an issue row carries a crossbridge answer-back substate — the terminal
/// issues recovery must still reconcile (re-deliver, or complete the crash-window
/// close) rather than short-circuit past (review #3).
fn carries_answer_substate(issue: &crate::state::IssueRow) -> bool {
    matches!(
        issue
            .phase_substate
            .as_deref()
            .and_then(PhaseSubstate::from_db_str),
        Some(
            PhaseSubstate::AnswerPending
                | PhaseSubstate::AnswerSent
                | PhaseSubstate::AnswerUnreachable
        )
    )
}

/// Decide how to recover an issue found mid-phase on orchestrator restart — the
/// pure decision table (REQ-15).
///
/// `substate` is the raw `phase_substate` column value (REQ-2a). An unrecognized
/// non-null value yields [`RecoveryError::UnknownSubstate`] — the signal that a
/// newer binary wrote state this one cannot interpret. `has_worker` is whether an
/// `active_workers` row exists for the issue (a live worker was in flight when
/// the orchestrator died); `has_done` is the re-derived filesystem ground truth —
/// whether that worker's workspace holds a verified `_orchestrator/DONE` (pass
/// `false` when there is no worker).
///
/// The `has_worker` discriminator is load-bearing for idempotence: a worker phase
/// **without** a worker row is not a crash to clean but a normal drivable state —
/// the pump requeues a QA-failed issue to `implementing` with no worker row, and
/// a fresh recovery pass must leave that alone (`NoAction`), not "clean" it every
/// time. Only a worker phase **with** a row (a genuinely in-flight worker) is
/// reconciled.
///
/// This is **total** over every `Phase`×`PhaseSubstate` pairing: a substate that
/// cannot belong to the phase it was found under is a state.db inconsistency and
/// yields [`RecoveryError::StateDbInconsistent`], never a silent fall-through.
pub fn plan_recovery(
    phase: Phase,
    substate: Option<&str>,
    has_worker: bool,
    has_done: bool,
) -> Result<RecoveryPlan, RecoveryError> {
    let substate =
        match substate {
            None => None,
            Some(raw) => Some(PhaseSubstate::from_db_str(raw).ok_or_else(|| {
                RecoveryError::UnknownSubstate {
                    phase: phase.to_string(),
                    substate: raw.to_string(),
                }
            })?),
        };

    // Crossbridge answer-back substates (spec §1.3/§1.4) ride a TERMINAL phase:
    // an `xb:inbound` issue that reached `Merged`/`PrOpen`/`AwaitingHumanMerge`/
    // `OrchestratorError` carries one of these to track delivery of its result to
    // the source peer. Recognize them EXPLICITLY here — before the terminal
    // short-circuit below — so the crash arms are legible.
    //
    // The phase-consistency check runs FIRST (review #5): an answer substate on a
    // NON-terminal phase is a corrupt state.db row (impossible pairing), so it is
    // `StateDbInconsistent` — NOT `NoAction`. Returning `NoAction` there would let
    // the answer sweep, which keys only off the substate, attempt delivery on a
    // non-terminal issue. This keeps `plan_recovery` total over every Phase×
    // Substate pairing, as its doc promises.
    //
    //  - `answer_pending` / `answer_unreachable` → **re-attempt**. There is no
    //    workspace or landing action to take; the pump's answer sweep re-reads
    //    the preserved substate on the next tick and re-delivers. So the plan is
    //    `NoAction` (recovery leaves the substate in place) and the sweep does the
    //    actual re-send — safe because crossbridge dedups on the source side, so a
    //    re-send never double-answers (spec §1.4). We keep NO local sent-ledger.
    //  - `answer_sent` → **complete the close** ([`RecoveryPlan::CompleteAnswerClose`]).
    //    The answer landed, but `record_success` persists `answer_sent` BEFORE the
    //    idempotent courtesy-label + `close_issue`; a crash in that window leaves
    //    the answered issue dangling OPEN forever (review #3). Recovery re-applies
    //    the label + close idempotently so it can't zombie.
    match substate {
        Some(sub @ PhaseSubstate::AnswerPending)
        | Some(sub @ PhaseSubstate::AnswerUnreachable)
        | Some(sub @ PhaseSubstate::AnswerSent) => {
            if !is_terminal(phase) {
                return Err(RecoveryError::StateDbInconsistent {
                    detail: format!(
                        "answer substate `{}` on non-terminal phase `{}` — impossible pairing",
                        sub.as_str(),
                        phase
                    ),
                });
            }
            return Ok(match sub {
                PhaseSubstate::AnswerSent => RecoveryPlan::CompleteAnswerClose,
                // AnswerPending / AnswerUnreachable: the sweep re-delivers.
                _ => RecoveryPlan::NoAction,
            });
        }
        _ => {}
    }

    // Terminal phases are never recovered, whatever substate they carry.
    if is_terminal(phase) {
        return Ok(RecoveryPlan::NoAction);
    }

    match (phase, substate) {
        // Freshly graphed, never driven — the pump owns it.
        (Phase::Graphed, None) => Ok(RecoveryPlan::NoAction),

        // Worker phase (implementing). Classify by whether a worker was in flight
        // and, if so, by the DONE ground truth (REQ-15):
        //  - no worker row  ⇒ a clean requeued/waiting state; leave it for the pump.
        //  - worker + DONE  ⇒ finished-but-un-advanced; replay translation, redrive.
        //  - worker, no DONE ⇒ crashed mid-work; clean + redrive fresh.
        (Phase::Implementing, None) => {
            if !has_worker {
                Ok(RecoveryPlan::NoAction)
            } else if has_done {
                Ok(RecoveryPlan::ReplayDoneThenRedrive)
            } else {
                Ok(RecoveryPlan::CleanCrashedWorker)
            }
        }

        // qa-gate is re-runnable and not crash-fragile. With a worker row (a
        // genuine mid-QA crash) clean the workspace and re-drive from
        // implementing; without one, the issue is only *at* qa-gate mid-crash, so
        // roll it back to implementing so the pump re-runs implement→QA. Either
        // way it lands at implementing, which a second pass leaves alone.
        (Phase::QaGate, None)
        | (Phase::QaGate, Some(PhaseSubstate::QaRunning))
        | (Phase::QaGate, Some(PhaseSubstate::QaPassedPendingTransition)) => {
            Ok(RecoveryPlan::CleanCrashedWorker)
        }

        // Local landing substates: delegate to the resumable landing machine
        // (AC-18). `Merging` (a crash while a Merger was resolving a conflict,
        // REQ-19) is included: the landing machine's resume path parks it for a
        // human (REQ-15a) rather than blindly re-driving an in-flight worker —
        // safe, since `main` is untouched. `recover` additionally reaps the
        // in-flight Merger row + its workspace before that park (F1), so neither
        // leaks once the issue goes terminal.
        (Phase::Landing, Some(sub @ PhaseSubstate::RebaseStarted))
        | (Phase::Landing, Some(sub @ PhaseSubstate::RebaseDoneBookmarkPending))
        | (Phase::Landing, Some(sub @ PhaseSubstate::Merging))
        | (Phase::Landing, Some(sub @ PhaseSubstate::BookmarkMovedComplete)) => {
            Ok(RecoveryPlan::ResumeLanding { substate: sub })
        }

        // Remote-mode landing substates (REQ-17 remote path): delegate to the
        // resumable remote-landing machine so a crash mid push/PR-create RESUMES
        // (re-point + re-push + adopt-or-create the PR, all idempotent) instead
        // of quarantining and orphaning the pushed branch (F1).
        (Phase::Landing, Some(sub @ PhaseSubstate::PushStarted))
        | (Phase::Landing, Some(sub @ PhaseSubstate::PushDonePrPending))
        | (Phase::Landing, Some(sub @ PhaseSubstate::PrCreated)) => {
            Ok(RecoveryPlan::ResumeRemoteLanding { substate: sub })
        }

        // Converged but never entered landing: land from the top (idempotent).
        (Phase::Converged, None) => Ok(RecoveryPlan::StartLanding),

        // iteration-2+ adversary review is not driven by the MVP pump; roll it
        // back to implementing so the pump re-drives it conservatively.
        (Phase::AdversaryReview, None) => Ok(RecoveryPlan::CleanCrashedWorker),

        // Any remaining pairing is an inconsistency: a substate that cannot
        // belong to the phase it was persisted under (e.g. a `landing` substate
        // on `implementing`, or a `qa` substate on `landing`). Refuse to advance
        // rather than guess.
        (phase, substate) => Err(RecoveryError::StateDbInconsistent {
            detail: format!(
                "phase `{}` with substate `{}` is not a recognized recoverable combination",
                phase,
                substate
                    .map(|s| s.as_str().to_owned())
                    .unwrap_or_else(|| "<none>".to_owned()),
            ),
        }),
    }
}

/// Run the deterministic crash-recovery table (REQ-15) over `state.db`.
///
/// For every non-terminal issue it re-derives ground truth from the filesystem
/// (the `DONE` sentinel, the jj graph via `manager`, the `main` bookmark) and
/// applies [`plan_recovery`]'s decision, in `list_issues` order (lexicographic
/// by `issue_id`). Returns the list of [`RecoveryAction`]s taken (issues left
/// untouched produce none).
///
/// `crosslink` is optional: it is needed only to *post* the idempotent
/// translation of a finished-but-un-advanced worker's artifacts (AC-17). When
/// `None`, that translation is skipped (its comments will be re-posted when the
/// pump re-drives), but the workspace cleanup + rollback still happen.
///
/// # Per-issue quarantine
///
/// Each issue is recovered independently: a failure recovering *one* issue (a
/// state.db inconsistency, an unknown substate, a jj-op failure while resuming
/// its landing) does **not** propagate out and refuse startup for the whole
/// node. Instead that issue is quarantined — parked at `phase:orchestrator-error`
/// so the pump skips it — a [`RecoveryAction::Quarantined`] is recorded, an event
/// is emitted, and the pass continues with the remaining issues. `recover` only
/// returns `Err` for a genuinely global failure (e.g. `state.db` unreadable, so
/// no issue can be classified at all).
///
/// Idempotent: a second `recover` finds every issue already reconciled and takes
/// no further action, yielding the same final state (asserted in the tests). A
/// quarantined issue is now terminal (`orchestrator-error`), so the second pass
/// skips it.
pub fn recover(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    crosslink: Option<&CrosslinkRepo>,
) -> Result<Vec<RecoveryAction>, RecoveryError> {
    // Resolve a PR opener for any remote-landing resume (F1), built from the SAME
    // remote the branch was pushed to (F3). A build failure (no GitHub token, a
    // non-GitHub remote, or local mode) is non-fatal: the opener stays `None` and
    // a remote-landing substate is then quarantined rather than resumed — never
    // worse than the pre-F1 behavior. Tests inject a fake via
    // [`recover_with_opener`].
    let opener = production_remote_opener(manager, crosslink);
    recover_with(state, log, manager, crosslink, opener.as_deref())
}

/// Like [`recover`], but with an explicit [`PrOpener`] for remote-landing
/// resumes — the seam through which tests drive a deterministic recovery with a
/// fake opener (production resolves an [`OctocrabPrOpener`] via [`recover`]).
pub fn recover_with_opener(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    crosslink: Option<&CrosslinkRepo>,
    opener: &dyn PrOpener,
) -> Result<Vec<RecoveryAction>, RecoveryError> {
    recover_with(state, log, manager, crosslink, Some(opener))
}

/// Build the production remote PR opener if remote mode is configured and a token
/// is available, else `None` (non-fatal — see [`recover`]).
fn production_remote_opener(
    manager: &WorkspaceManager,
    crosslink: Option<&CrosslinkRepo>,
) -> Option<Box<dyn PrOpener>> {
    let remote = crosslink?.tracker_remote().ok().flatten()?;
    OctocrabPrOpener::for_remote(manager, &remote)
        .ok()
        .map(|opener| Box::new(opener) as Box<dyn PrOpener>)
}

/// The shared recovery pass: iterate `state.db` and reconcile each non-terminal
/// issue, using `opener` for any remote-landing resume.
fn recover_with(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    crosslink: Option<&CrosslinkRepo>,
    opener: Option<&dyn PrOpener>,
) -> Result<Vec<RecoveryAction>, RecoveryError> {
    // A failure to even *read* the issue / worker lists is a global fault: no
    // issue can be classified, so recovery cannot proceed at all. This is the
    // only path that returns `Err` from `recover` — per-issue faults quarantine.
    let issues = state.list_issues().map_err(state_err)?;
    let workers = state.list_active_workers().map_err(state_err)?;

    let mut actions = Vec::new();
    for issue in issues {
        // Terminal issues are done and skipped — EXCEPT an `xb:inbound` issue still
        // carrying an answer substate. Those need reconciliation: `answer_sent` may
        // be an un-closed crash-window zombie (review #3), and `answer_pending` /
        // `answer_unreachable` are left in place (NoAction) for the sweep to
        // re-deliver. Route only those terminal issues into `recover_issue`; the
        // bulk of terminal issues (a merged issue with no answer substate) still
        // short-circuits here.
        if is_terminal(issue.phase) && !carries_answer_substate(&issue) {
            continue;
        }
        // Recover this one issue in isolation. On error, quarantine it and keep
        // going — one poison issue must never brick the whole node's startup.
        match recover_issue(state, log, manager, crosslink, opener, &issue, &workers) {
            Ok(mut issue_actions) => actions.append(&mut issue_actions),
            Err(err) => {
                let reason = err.to_string();
                quarantine(state, log, &issue.issue_id, &reason)?;
                actions.push(RecoveryAction::Quarantined {
                    issue_id: issue.issue_id.clone(),
                    reason,
                });
            }
        }
    }
    Ok(actions)
}

/// Recover exactly one issue, returning the [`RecoveryAction`]s it produced (0+).
///
/// Errors are the caller's ([`recover`]) quarantine signal — this function never
/// touches `phase:orchestrator-error` itself; it either reconciles the issue or
/// reports why it couldn't.
fn recover_issue(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    crosslink: Option<&CrosslinkRepo>,
    opener: Option<&dyn PrOpener>,
    issue: &crate::state::IssueRow,
    workers: &[ActiveWorkerRow],
) -> Result<Vec<RecoveryAction>, RecoveryError> {
    // ALL worker rows for this issue — a crash can leave more than one (a stale
    // attempt plus a retry). The first is the ground-truth source for the DONE
    // check and cleanup; any extras are reconciled below so none leak (#3).
    let issue_workers: Vec<&ActiveWorkerRow> = workers
        .iter()
        .filter(|w| w.issue_id == issue.issue_id)
        .collect();
    let worker = issue_workers.first().copied();

    // Re-derive the DONE ground truth for worker phases from the worker's
    // persisted workspace (REQ-15). No worker row ⇒ no DONE to find.
    let has_done = match worker {
        Some(w) => done_present(w),
        None => false,
    };

    let plan = plan_recovery(
        issue.phase,
        issue.phase_substate.as_deref(),
        worker.is_some(),
        has_done,
    )?;

    let mut actions = Vec::new();
    match plan {
        RecoveryPlan::NoAction => {}

        RecoveryPlan::CleanCrashedWorker => {
            clean_crashed_worker(state, log, manager, &issue.issue_id, worker)?;
            actions.push(RecoveryAction::CleanedCrashedWorker {
                issue_id: issue.issue_id.clone(),
            });
        }

        RecoveryPlan::ReplayDoneThenRedrive => {
            // Safety: `has_done` was true, which is only reachable with a
            // worker row present (see `has_done` above).
            let worker = worker.ok_or_else(|| RecoveryError::StateDbInconsistent {
                detail: format!(
                    "issue `{}` planned ReplayDone but has no active_workers row",
                    issue.issue_id
                ),
            })?;
            let posted = replay_done(state, manager, crosslink, &issue.issue_id, worker)?;
            clean_crashed_worker(state, log, manager, &issue.issue_id, Some(worker))?;
            actions.push(RecoveryAction::ReplayedDone {
                issue_id: issue.issue_id.clone(),
                posted,
            });
        }

        RecoveryPlan::ResumeLanding { substate } => {
            // F1: a crash *during* Merger resolution (REQ-19) left an in-flight
            // Merger `active_workers` row and its `landing-<id>-r<round>-<uuid>`
            // workspace on disk. `resume_from(Merging)` parks the issue for a
            // human (safe — `main` is untouched) but does NOT reclaim that worker
            // or its workspace, and the reaper loop below only reaps rows *beyond*
            // the first — so the in-flight Merger (the first, and typically only,
            // row) would leak forever once the issue goes terminal. Reap it here,
            // BEFORE parking, using the same forget+row-drop primitives the
            // `CleanCrashedWorker` plan uses (but NOT its implementing rollback —
            // the merge must still park, not re-drive). Idempotent: a second pass
            // finds the issue terminal (`awaiting-human-merge`) and never
            // re-enters, and `forget`/`remove_worker` are no-ops on an absent
            // workspace/row regardless.
            if substate == PhaseSubstate::Merging {
                if let Some(merger) = worker {
                    if let Some(name) = workspace_name_from(merger) {
                        let _ = manager.forget(&name);
                    }
                    let _ = state.remove_worker(&merger.worker_uuid);
                }
            }
            // Resolve the landing change lazily: `BookmarkMovedComplete` completes
            // from bookmark ground truth alone, and `Merging` parks for a human
            // without touching the change — neither needs the workspace, so a
            // missing implement workspace must not brick a resume that could
            // finish. Only resolve when the plan actually needs a change revset.
            let outcome = if matches!(
                substate,
                PhaseSubstate::BookmarkMovedComplete | PhaseSubstate::Merging
            ) {
                // The change target is unused by the terminal-transition step;
                // pass a placeholder — `resume_from` never resolves it here.
                landing::resume_from(state, log, manager, &issue.issue_id, "", substate)
                    .map_err(landing_err)?
            } else {
                // Resolve the change to complete the landing from. An
                // approved-inbound resume (`park_for_inbound_approval` →
                // `resume_approved_inbound` → `land`) persisted the exact
                // human-reviewed change in `issues.landing_change` at park time,
                // PRECISELY because its Implementer workspace is already forgotten by
                // landing time — so the workspace scan below cannot re-derive it and
                // would quarantine the issue instead of completing it. When that
                // durable handle is present, complete the landing from THAT stored
                // change: it lands exactly the change a human approved (a security
                // property), and `resume_from(RebaseStarted)` is idempotent — a
                // change already a descendant of `main` is a fast-forward no-op, so a
                // crash mid-recovery-land re-completes safely.
                //
                // A normal (non-inbound) landing leaves `landing_change` null and is
                // re-derived from the live `implementing` workspace exactly as before
                // — behavior on that path is UNCHANGED.
                let change = match &issue.landing_change {
                    Some(stored) => stored.clone(),
                    None => landing_change_revset(manager, &issue.issue_id, issue.round)?,
                };
                landing::resume_from(state, log, manager, &issue.issue_id, &change, substate)
                    .map_err(landing_err)?
            };
            actions.push(RecoveryAction::ResumedLanding {
                issue_id: issue.issue_id.clone(),
                outcome,
            });
        }

        RecoveryPlan::ResumeRemoteLanding { substate } => {
            let outcome =
                resume_remote_landing(state, log, manager, crosslink, opener, issue, substate)?;
            actions.push(RecoveryAction::ResumedLanding {
                issue_id: issue.issue_id.clone(),
                outcome,
            });
        }

        RecoveryPlan::StartLanding => {
            let change = landing_change_revset(manager, &issue.issue_id, issue.round)?;
            let outcome =
                land_local(state, log, manager, &issue.issue_id, &change).map_err(landing_err)?;
            actions.push(RecoveryAction::StartedLanding {
                issue_id: issue.issue_id.clone(),
                outcome,
            });
        }

        RecoveryPlan::CompleteAnswerClose => {
            // Crash-window zombie (review #3): the answer was recorded
            // (`answer_sent`) but a crash may have preceded the idempotent
            // courtesy-label + close. Re-apply both. Needs a crosslink handle;
            // without one (recovery invoked with `None`) leave it for a later
            // restart that has crosslink — never worse than the pre-fix behavior.
            if let Some(crosslink) = crosslink {
                if complete_answer_close(crosslink, &issue.issue_id)? {
                    actions.push(RecoveryAction::CompletedAnswerClose {
                        issue_id: issue.issue_id.clone(),
                    });
                }
            }
        }
    }

    // Reap any EXTRA worker rows for this issue beyond the one the plan handled
    // (#3): a crash can register a retry before the prior attempt's row was
    // dropped. Left behind, they'd leak and re-trigger recovery. The plan's own
    // paths already dropped `worker` (the first row); drop the rest here. This
    // runs for every plan, including `NoAction`, so a stray row on an otherwise
    // clean issue is still reclaimed.
    for extra in issue_workers.iter().skip(1) {
        if let Some(name) = workspace_name_from(extra) {
            let _ = manager.forget(&name);
        }
        let _ = state.remove_worker(&extra.worker_uuid);
    }

    Ok(actions)
}

/// Complete a crash-window answer close idempotently (review #3): if the answered
/// issue is still **open**, re-apply the `xb-status:answered` courtesy label and
/// close it. Returns whether it actually reconciled a zombie (`true` if the issue
/// was open and is now closed, `false` if it was already closed — the second-pass
/// / no-crash case), so [`recover`] records a
/// [`RecoveryAction::CompletedAnswerClose`] only for a real reconciliation.
///
/// The open/closed decision reads the issue status directly rather than trusting
/// `close_issue`'s return value, whose "did something" bool is unreliable through
/// the shared-writer (hub-mode) path — an already-closed close still reports
/// success there. A crosslink fault maps to [`RecoveryError::StateDbInconsistent`],
/// which the caller quarantines.
fn complete_answer_close(crosslink: &CrosslinkRepo, issue_id: &str) -> Result<bool, RecoveryError> {
    let numeric_id: i64 = issue_id
        .parse()
        .map_err(|_| RecoveryError::StateDbInconsistent {
            detail: format!("answer issue id `{issue_id}` is not an integer"),
        })?;
    let info =
        crosslink
            .read_issue(numeric_id)
            .map_err(|source| RecoveryError::StateDbInconsistent {
                detail: format!("answer-close read for issue `{issue_id}` failed: {source}"),
            })?;
    // Already closed/archived — the close completed before the crash, or a prior
    // recovery pass did it. Nothing to reconcile; keep this idempotent.
    if info.status != "open" {
        return Ok(false);
    }
    crosslink
        .label_add(numeric_id, XB_STATUS_ANSWERED)
        .map_err(|source| RecoveryError::StateDbInconsistent {
            detail: format!("answer-close label for issue `{issue_id}` failed: {source}"),
        })?;
    crosslink
        .close_issue(numeric_id)
        .map_err(|source| RecoveryError::StateDbInconsistent {
            detail: format!("answer-close for issue `{issue_id}` failed: {source}"),
        })?;
    Ok(true)
}

/// Whether the worker's workspace holds a verified `_orchestrator/DONE`.
///
/// Ground truth for the worker-phase branch of the table (REQ-15): a present +
/// fully-valid DONE means the worker finished cleanly; anything else (absent,
/// torn, sha-mismatched) is treated as "no DONE" → the crash-cleanup path.
fn done_present(worker: &ActiveWorkerRow) -> bool {
    DoneSentinel::verify(&worker.workspace_path).is_ok()
}

/// Clean a crashed/finished worker: best-effort kill (a pane-hosted worker is
/// already gone after a process death, and P1 persists no pid, so there is
/// nothing to signal — the `forget`+`rm -rf` below is the real cleanup), forget
/// and remove its workspace, drop the `active_workers` row, and roll the issue
/// to `implementing` so the pump re-drives it fresh (REQ-8).
///
/// Idempotent: `forget` no-ops on an absent workspace, `remove_worker` no-ops on
/// an absent row, and re-setting `implementing` on an already-`implementing`
/// issue is a no-op write. A second recovery pass thus finds nothing to do.
fn clean_crashed_worker(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    issue_id: &str,
    worker: Option<&ActiveWorkerRow>,
) -> Result<(), RecoveryError> {
    // Best-effort workspace cleanup: derive the workspace name from the persisted
    // path and forget+rm it. A path we can't parse into a WorkspaceName means the
    // row is malformed; skip the jj forget (the directory removal below still
    // runs) rather than fail recovery.
    if let Some(worker) = worker {
        if let Some(name) = workspace_name_from(worker) {
            // `forget` is idempotent (no-op if not registered / dir absent).
            let _ = manager.forget(&name);
        }
        let _ = state.remove_worker(&worker.worker_uuid);
    }

    // Roll the issue back to implementing (drivable). If it is already there this
    // is a no-op write; the pump re-preps a fresh workspace on the next tick.
    let from = state
        .get_issue(issue_id)
        .map_err(state_err)?
        .map(|i| i.phase)
        .unwrap_or(Phase::Implementing);
    state
        .set_phase(issue_id, Phase::Implementing, None)
        .map_err(state_err)?;
    emit_recovery(
        log,
        state,
        issue_id,
        &format!(
            "recovery: rolled `{from}` back to `implementing` after cleaning a crashed worker"
        ),
    )?;
    Ok(())
}

/// Re-run the idempotent artifact translation for a finished worker (AC-17).
///
/// The worker wrote a valid `DONE` before the orchestrator crashed, so its
/// artifacts are intact. This re-verifies the DONE, rebuilds the *pure*
/// translation plan, and posts each comment **at most once** by checking the
/// content-addressed `posted_artifacts` ledger keyed on `(issue_id,
/// artifact_path, content_sha, finding_index)` — a crash mid-translation replays
/// here and the ledger suppresses everything already posted, and because the key
/// is NOT the uuid the pump's subsequent re-drive (fresh uuid, same content) is
/// also a no-op. Returns how many comments this pass actually posted (0 on a
/// full replay — the idempotency signal AC-17 asserts).
///
/// `crosslink` is optional; when `None` (or the issue id is not a crosslink
/// numeric id) the translation is skipped and 0 is returned — the pump's
/// re-drive will post the comments instead.
///
/// If the DONE has vanished between the `done_present` classification and here
/// (a torn write racing recovery), this does **not** hard-abort: the replay is
/// simply skipped (0 posted) and the caller cleans + re-drives from
/// `implementing`, so the pump re-produces the work. A vanished DONE is exactly
/// the crashed-worker case, so degrading to clean+redrive is the correct action,
/// not a quarantine.
fn replay_done(
    state: &StateDb,
    manager: &WorkspaceManager,
    crosslink: Option<&CrosslinkRepo>,
    issue_id: &str,
    worker: &ActiveWorkerRow,
) -> Result<usize, RecoveryError> {
    let _ = manager; // ground truth already read via done_present; kept for parity.
    let (Some(crosslink), Ok(numeric_id)) = (crosslink, issue_id.parse::<i64>()) else {
        return Ok(0);
    };
    // Only the Implementer's result translation is replayed here (the MVP worker
    // role). A verified DONE is required to build the set; it was checked to be
    // present by `done_present`. If it vanished in the race window, degrade to
    // clean+redrive (the caller cleans and rolls back) rather than aborting.
    let Ok(done) = DoneSentinel::verify(&worker.workspace_path) else {
        return Ok(0);
    };
    let set = ArtifactSet { done };
    let plan = crate::artifacts::translation_plan(&worker.worker_uuid, &set).map_err(|source| {
        RecoveryError::StateDbInconsistent {
            detail: format!("replay translation plan for issue `{issue_id}` failed: {source}"),
        }
    })?;

    let mut posted = 0usize;
    for item in plan {
        // Ledger check first: a tuple already recorded (by this attempt OR any
        // other attempt for this issue) is a no-op. Content-addressed key.
        if state
            .is_posted(
                issue_id,
                &item.artifact_path,
                &item.content_sha,
                item.finding_index,
            )
            .map_err(state_err)?
        {
            continue;
        }
        let comment_id = crosslink
            .comment_write(
                numeric_id,
                item.kind.as_str(),
                &item.body,
                Some(WORKER_ROLE_TAG),
            )
            .map_err(|source| RecoveryError::StateDbInconsistent {
                detail: format!("replay comment post for issue `{issue_id}` failed: {source}"),
            })?;
        state
            .record_posted(&PostedArtifact {
                issue_id: issue_id.to_owned(),
                artifact_path: item.artifact_path,
                content_sha: item.content_sha,
                finding_index: item.finding_index,
                worker_uuid: worker.worker_uuid.clone(),
                comment_id: comment_id.to_string(),
                posted_at: now_unix(),
            })
            .map_err(state_err)?;
        posted += 1;
    }
    Ok(posted)
}

/// Quarantine an issue whose recovery failed: park it at
/// `phase:orchestrator-error` (an undrivable, terminal phase the pump skips) and
/// emit an event recording why. Called by [`recover`] instead of propagating a
/// per-issue error out — one poison issue must not refuse startup for the node.
///
/// Returns `Err` only if the quarantine *itself* can't be written (a state.db
/// write failure), which is a genuine global fault the caller does surface.
fn quarantine(
    state: &StateDb,
    log: &EventLog,
    issue_id: &str,
    reason: &str,
) -> Result<(), RecoveryError> {
    state
        .set_phase(issue_id, Phase::OrchestratorError, None)
        .map_err(state_err)?;
    emit(
        state,
        log,
        EventKind::Transition,
        Some(issue_id),
        None,
        &json!({
            "recovery": true,
            "quarantine": true,
            "to_phase": Phase::OrchestratorError.as_str(),
            "reason": reason,
        }),
    )
    .map(|_id| ())
    .map_err(state_err)
}

/// Re-derive the `change_revset` for a landing recovery: the working-copy commit
/// id of the implement workspace the pump landed from (REQ-15, mirroring the
/// pump's own `change_revset`).
///
/// The pump lands from the `implementing-<issue>-r<round>-<uuid>` workspace, so
/// recovery scans the live workspace list for the one whose parsed name matches
/// this issue at this round and returns its working-copy commit id. If no such
/// workspace is registered (it was already forgotten, or the crash predates its
/// creation) recovery cannot reconstruct the target and refuses.
///
/// KNOWN LIMITATION (F3, fails safe): after a crash at
/// `RebaseDoneBookmarkPending` that followed a Merger's
/// [`retry_land_after_merge`](landing::retry_land_after_merge), the change this
/// re-derives is the ORIGINAL, still-unmerged `implementing` commit — NOT the
/// Merger's resolved commit (this scan only knows the `implementing` workspace).
/// `main` is not an ancestor of that stale target, so the FF-guard refuses the
/// move and the issue parks at `awaiting-human-merge`. That is safe (`main` is
/// never rewound) but it DISCARDS a good merge rather than resuming it — the
/// post-merge case is deliberately not resumed here, only re-derivable landings
/// are. A human applying `human-resolved:retry` re-drives the landing.
fn landing_change_revset(
    manager: &WorkspaceManager,
    issue_id: &str,
    round: i64,
) -> Result<String, RecoveryError> {
    let want_round = round.max(0) as u32;
    let entries = manager
        .entries()
        .map_err(|source| RecoveryError::StateDbInconsistent {
            detail: format!(
                "could not list jj workspaces to recover landing for `{issue_id}`: {source}"
            ),
        })?;
    for entry in entries {
        let Some(name) = WorkspaceName::parse(&entry.name) else {
            continue;
        };
        if name.phase() == Phase::Implementing
            && name.round() == want_round
            && workspace_issue_matches(&name, issue_id)
        {
            return Ok(entry.working_copy_id);
        }
    }
    Err(RecoveryError::StateDbInconsistent {
        detail: format!(
            "no `implementing` workspace for issue `{issue_id}` round {want_round} to recover the \
             landing change from — cannot resume landing"
        ),
    })
}

/// Resume a remote-mode landing found mid-flight on restart (F1).
///
/// Reconstructs the [`RemoteLanding`] inputs the same way the pump's
/// `land_remote_mode` does — the per-issue branch (`vdd/<id>-<slug>`) from the
/// crosslink issue title, the PR base/title/body — and delegates to
/// [`landing::resume_remote_from`] with the persisted substate and the injected
/// PR `opener`. The push is idempotent (re-point + re-push) and PR creation is
/// idempotent (an existing open PR is adopted, never re-created), so this
/// completes deterministically without a duplicate PR or a double-push.
///
/// The reviewed change's revset is the pushed **branch bookmark itself**: by the
/// time landing runs, the pump has already forgotten the Implementer workspace
/// (it does so before adversary review), so there is no `implementing` workspace
/// to scan — but the branch the machine pushed points at exactly the reviewed
/// change, and is a stable revset for it. A `push_started` resume re-points the
/// branch at itself (a jj no-op) and re-pushes; the later substates never touch
/// it.
///
/// Missing prerequisites (no PR opener — remote mode without a token; no
/// crosslink handle; a non-numeric issue id; no configured `tracker_remote`) are
/// [`RecoveryError::StateDbInconsistent`], which the caller quarantines — a safe
/// fallback that is never worse than the pre-F1 unconditional quarantine.
fn resume_remote_landing(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    crosslink: Option<&CrosslinkRepo>,
    opener: Option<&dyn PrOpener>,
    issue: &crate::state::IssueRow,
    substate: PhaseSubstate,
) -> Result<landing::LandingOutcome, RecoveryError> {
    let issue_id = &issue.issue_id;
    let opener = opener.ok_or_else(|| RecoveryError::StateDbInconsistent {
        detail: format!(
            "issue `{issue_id}` is mid remote-landing (`{}`) but no GitHub PR opener is \
             configured (remote mode needs a GH_TOKEN/GITHUB_TOKEN and a GitHub remote) — \
             cannot resume",
            substate.as_str()
        ),
    })?;
    let crosslink = crosslink.ok_or_else(|| RecoveryError::StateDbInconsistent {
        detail: format!(
            "issue `{issue_id}` is mid remote-landing but recovery has no crosslink handle to \
             reconstruct its branch and PR inputs"
        ),
    })?;
    let remote = crosslink
        .tracker_remote()
        .map_err(|source| RecoveryError::StateDbInconsistent {
            detail: format!("could not read `tracker_remote` recovering `{issue_id}`: {source}"),
        })?
        .ok_or_else(|| RecoveryError::StateDbInconsistent {
            detail: format!(
                "issue `{issue_id}` is mid remote-landing but `tracker_remote` is now unset — \
                 cannot resume the push target"
            ),
        })?;
    let numeric_id = issue_id
        .parse::<i64>()
        .map_err(|_| RecoveryError::StateDbInconsistent {
            detail: format!(
                "issue `{issue_id}` is mid remote-landing but its id is not numeric — cannot read \
                 the crosslink issue to reconstruct the PR inputs"
            ),
        })?;
    let info =
        crosslink
            .read_issue(numeric_id)
            .map_err(|source| RecoveryError::StateDbInconsistent {
                detail: format!("could not read crosslink issue `{issue_id}` to resume its remote landing: {source}"),
            })?;
    let branch = branch_name(issue_id, &info.title);
    let title = info.title.clone();
    let body = info
        .description
        .clone()
        .unwrap_or_else(|| info.title.clone());
    // The pushed branch bookmark is the reviewed change's revset (see the doc
    // comment): the implement workspace is already gone by landing time.
    let params = RemoteLanding {
        issue_id,
        change_revset: &branch,
        remote: &remote,
        branch: &branch,
        base: MAIN_BOOKMARK,
        title: &title,
        body: &body,
    };
    landing::resume_remote_from(state, log, manager, opener, &params, substate).map_err(landing_err)
}

/// Whether a parsed workspace name belongs to `issue_id`. The name's issue
/// segment is the *sanitized* issue id (see [`WorkspaceName`]); rather than
/// re-expose the sanitizer, we re-derive the expected name from the typed
/// components and compare the rendered strings — an exact, allocation-cheap
/// match that cannot drift from the generator.
fn workspace_issue_matches(name: &WorkspaceName, issue_id: &str) -> bool {
    let expected = WorkspaceName::generate(name.phase(), issue_id, name.round());
    // `generate` mints a fresh uuid, so compare only the phase/issue/round
    // prefix by stripping the trailing `-<uuid>` from both rendered names.
    strip_uuid(&expected.as_str()) == strip_uuid(&name.as_str())
}

/// Strip the trailing `-<uuid>` segment from a rendered workspace name, leaving
/// the `<phase>-<issue>-r<round>` prefix. Used to compare two names for the same
/// issue/round while ignoring their (necessarily distinct) uuid suffixes.
fn strip_uuid(rendered: &str) -> &str {
    rendered
        .rsplit_once('-')
        .map(|(head, _)| head)
        .unwrap_or(rendered)
}

/// Parse the workspace name a worker row's persisted directory encodes.
///
/// The `active_workers.workspace_path` is `<root>/.workspace/<name>`; the final
/// path component is the rendered [`WorkspaceName`], re-parsed here so recovery
/// can drive `manager.forget(&name)`. Returns `None` if the path has no final
/// component or it is not a name this scheme could have produced.
fn workspace_name_from(worker: &ActiveWorkerRow) -> Option<WorkspaceName> {
    let leaf = worker.workspace_path.file_name()?.to_str()?;
    WorkspaceName::parse(leaf)
}

/// Emit a recovery transition event to both `state.db` and `events.jsonl`,
/// mapping the write failure into the recovery error surface.
fn emit_recovery(
    log: &EventLog,
    state: &StateDb,
    issue_id: &str,
    reason: &str,
) -> Result<(), RecoveryError> {
    emit(
        state,
        log,
        EventKind::Transition,
        Some(issue_id),
        None,
        &json!({ "recovery": true, "reason": reason }),
    )
    .map(|_id| ())
    .map_err(state_err)
}

/// Current time as unix seconds (0 before the epoch, never panics) — the
/// `posted_at` stamp for a replayed translation.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Wrap a `state.db` failure as the recovery inconsistency surface: a broken
/// authority means recovery cannot derive a consistent state.
fn state_err(source: vetinari_error::StateError) -> RecoveryError {
    RecoveryError::StateDbInconsistent {
        detail: format!("state.db operation failed during recovery: {source}"),
    }
}

/// Wrap a landing failure surfaced by the delegated resume as a recovery
/// inconsistency (a genuine jj-op failure, not the handled conflict/park
/// outcomes which land as [`landing::LandingOutcome`] values).
fn landing_err(source: vetinari_error::LandingError) -> RecoveryError {
    RecoveryError::StateDbInconsistent {
        detail: format!("landing resume failed during recovery: {source}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_phase_without_a_worker_row_is_left_for_the_pump() {
        // A requeued `implementing` issue (QA-failed → back to implementing, no
        // worker row) is a normal drivable state, not a crash — leave it.
        let plan = plan_recovery(Phase::Implementing, None, false, false).unwrap();
        assert_eq!(plan, RecoveryPlan::NoAction);
    }

    #[test]
    fn worker_phase_with_worker_and_no_done_cleans() {
        let plan = plan_recovery(Phase::Implementing, None, true, false).unwrap();
        assert_eq!(plan, RecoveryPlan::CleanCrashedWorker);
    }

    #[test]
    fn worker_phase_with_done_replays() {
        let plan = plan_recovery(Phase::Implementing, None, true, true).unwrap();
        assert_eq!(plan, RecoveryPlan::ReplayDoneThenRedrive);
    }

    #[test]
    fn graphed_is_left_for_the_pump() {
        assert_eq!(
            plan_recovery(Phase::Graphed, None, false, false).unwrap(),
            RecoveryPlan::NoAction
        );
    }

    #[test]
    fn terminal_phases_are_no_action() {
        for phase in [
            Phase::Merged,
            Phase::PrOpen,
            Phase::AwaitingHumanMerge,
            Phase::OrchestratorError,
        ] {
            assert_eq!(
                plan_recovery(phase, None, false, false).unwrap(),
                RecoveryPlan::NoAction,
                "{phase} must be no-action",
            );
        }
    }

    #[test]
    fn qa_substates_roll_back_to_implementing() {
        for token in [
            None,
            Some("qa_running"),
            Some("qa_passed_pending_transition"),
        ] {
            assert_eq!(
                plan_recovery(Phase::QaGate, token, true, false).unwrap(),
                RecoveryPlan::CleanCrashedWorker,
                "qa substate {token:?} must clean+redrive",
            );
        }
    }

    #[test]
    fn landing_substates_delegate_to_resume() {
        for (token, sub) in [
            ("rebase_started", PhaseSubstate::RebaseStarted),
            (
                "rebase_done_bookmark_pending",
                PhaseSubstate::RebaseDoneBookmarkPending,
            ),
            (
                "bookmark_moved_complete",
                PhaseSubstate::BookmarkMovedComplete,
            ),
            // `merging` (a crash during Merger resolution, REQ-19) is a landing
            // resume point too — it delegates to `resume_from`, which parks for a
            // human (the reap of the in-flight Merger row/workspace is `recover`'s
            // job, exercised by the behavioral test in `tests/recovery.rs`).
            ("merging", PhaseSubstate::Merging),
        ] {
            assert_eq!(
                plan_recovery(Phase::Landing, Some(token), false, false).unwrap(),
                RecoveryPlan::ResumeLanding { substate: sub },
            );
        }
    }

    #[test]
    fn answer_pending_and_unreachable_are_reattempted_by_the_sweep_not_recovery() {
        // Crash mid-answer (spec §1.4): an inbound issue at a terminal phase with
        // an `answer_pending` / `answer_unreachable` substate is left in place
        // (NoAction) so the pump's answer sweep re-delivers on the next tick —
        // crossbridge source-side dedup makes the re-send safe.
        for phase in [
            Phase::Merged,
            Phase::PrOpen,
            Phase::AwaitingHumanMerge,
            Phase::OrchestratorError,
        ] {
            for token in ["answer_pending", "answer_unreachable"] {
                assert_eq!(
                    plan_recovery(phase, Some(token), false, false).unwrap(),
                    RecoveryPlan::NoAction,
                    "{phase}/{token} must be left for the sweep to re-attempt",
                );
            }
        }
    }

    #[test]
    fn answer_sent_completes_the_crash_window_close() {
        // A completed answer is never re-sent, but its idempotent close may not
        // have happened before a crash (review #3) — recovery completes it.
        for phase in [
            Phase::Merged,
            Phase::PrOpen,
            Phase::AwaitingHumanMerge,
            Phase::OrchestratorError,
        ] {
            assert_eq!(
                plan_recovery(phase, Some("answer_sent"), false, false).unwrap(),
                RecoveryPlan::CompleteAnswerClose,
                "{phase}/answer_sent must complete the idempotent close",
            );
        }
    }

    #[test]
    fn answer_substate_on_non_terminal_phase_is_inconsistent() {
        // Review #5: an answer substate can only ride a TERMINAL phase. On a
        // non-terminal phase it is a corrupt row → StateDbInconsistent, NOT
        // NoAction (which would let the sweep attempt delivery on a live issue).
        for phase in [
            Phase::Graphed,
            Phase::Implementing,
            Phase::QaGate,
            Phase::AdversaryReview,
            Phase::Converged,
            Phase::Landing,
        ] {
            for token in ["answer_pending", "answer_unreachable", "answer_sent"] {
                let err = plan_recovery(phase, Some(token), false, false).unwrap_err();
                assert!(
                    matches!(err, RecoveryError::StateDbInconsistent { .. }),
                    "{phase}/{token} is an impossible pairing — must be StateDbInconsistent, got {err:?}",
                );
            }
        }
    }

    #[test]
    fn converged_starts_landing() {
        assert_eq!(
            plan_recovery(Phase::Converged, None, false, false).unwrap(),
            RecoveryPlan::StartLanding
        );
    }

    #[test]
    fn unknown_substate_is_rejected() {
        let err = plan_recovery(Phase::Landing, Some("frobnicate"), false, false).unwrap_err();
        match err {
            RecoveryError::UnknownSubstate { substate, .. } => {
                assert_eq!(substate, "frobnicate");
            }
            other => panic!("expected UnknownSubstate, got {other:?}"),
        }
    }

    #[test]
    fn inconsistent_phase_substate_pairing_is_rejected() {
        // A landing substate on a worker phase is not a recoverable combination.
        let err =
            plan_recovery(Phase::Implementing, Some("rebase_started"), true, false).unwrap_err();
        assert!(
            matches!(err, RecoveryError::StateDbInconsistent { .. }),
            "a landing substate on implementing must be a state.db inconsistency, got {err:?}"
        );
        // A qa substate on a landing phase is not a recoverable combination.
        let err = plan_recovery(Phase::Landing, Some("qa_running"), false, false).unwrap_err();
        assert!(
            matches!(err, RecoveryError::StateDbInconsistent { .. }),
            "a qa substate on landing must be a state.db inconsistency, got {err:?}"
        );
    }

    #[test]
    fn remote_landing_substates_delegate_to_remote_resume() {
        // The remote-mode landing substates now RESUME (F1) rather than
        // quarantining — each routes to the resumable remote-landing machine.
        for (token, sub) in [
            ("push_started", PhaseSubstate::PushStarted),
            ("push_done_pr_pending", PhaseSubstate::PushDonePrPending),
            ("pr_created", PhaseSubstate::PrCreated),
        ] {
            assert_eq!(
                plan_recovery(Phase::Landing, Some(token), false, false).unwrap(),
                RecoveryPlan::ResumeRemoteLanding { substate: sub },
                "remote landing substate `{token}` must resume, not quarantine",
            );
        }
    }

    #[test]
    fn plan_recovery_is_total_over_recognized_substates() {
        // Every (phase, substate) either yields a plan or a typed error — never
        // panics. Exercise the full cross product of phases × recognized
        // substates (+ None).
        let phases = [
            Phase::Graphed,
            Phase::Implementing,
            Phase::QaGate,
            Phase::AdversaryReview,
            Phase::Converged,
            Phase::Landing,
            Phase::Merged,
            Phase::PrOpen,
            Phase::AwaitingHumanMerge,
            Phase::OrchestratorError,
        ];
        let substates = [
            None,
            Some("qa_running"),
            Some("qa_passed_pending_transition"),
            Some("rebase_started"),
            Some("rebase_done_bookmark_pending"),
            Some("bookmark_moved_complete"),
            Some("push_started"),
            Some("push_done_pr_pending"),
            Some("pr_created"),
            Some("answer_pending"),
            Some("answer_sent"),
            Some("answer_unreachable"),
        ];
        for phase in phases {
            for substate in substates {
                for has_worker in [false, true] {
                    for has_done in [false, true] {
                        // Must return Ok(_) or Err(_) without panicking.
                        let _ = plan_recovery(phase, substate, has_worker, has_done);
                    }
                }
            }
        }
    }

    fn strip(s: &str) -> String {
        strip_uuid(s).to_owned()
    }

    #[test]
    fn strip_uuid_drops_only_the_trailing_segment() {
        assert_eq!(strip("implementing-42-r3-a1b2c3d4"), "implementing-42-r3");
    }

    #[test]
    fn workspace_issue_matches_ignores_uuid() {
        let a = WorkspaceName::generate(Phase::Implementing, "#42", 3);
        // Two distinct spawns for the same issue/round differ only in uuid.
        assert!(workspace_issue_matches(&a, "#42"));
        assert!(!workspace_issue_matches(&a, "#43"));
    }
}
