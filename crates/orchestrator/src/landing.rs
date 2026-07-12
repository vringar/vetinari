//! Local-mode landing: rebase a converged issue's change onto `main` and
//! fast-forward the `main` bookmark to it (REQ-17 local path, REQ-2a, AC-11a,
//! AC-18).
//!
//! After a worker's change passes QA, the orchestrator lands it *without* human
//! intervention: it rebases the issue's change onto the current `main`, then
//! moves the `main` bookmark to the landed change → `phase:merged`. A rebase
//! that conflicts is **not** an error — it parks the issue at
//! `phase:awaiting-human-merge` for a human (the Merger role, #L4, is deferred).
//!
//! # The substate machine (REQ-2a, AC-18 resumable)
//!
//! Landing is a multi-step `.jj/` mutation, so a crash between two jj ops must
//! be recoverable. The machine persists each [`PhaseSubstate`] to `state.db`
//! *between* the jj operations, so on restart the recovery path can read the
//! last-written substate and resume from exactly there:
//!
//! ```text
//!   set_phase(Landing, RebaseStarted)
//!   ├─ rebase(change, onto = main)   (idempotent: skipped if already on main)
//!   │   └─ has_conflict? ─▶ set_phase(AwaitingHumanMerge, None) ─▶ AwaitingHumanMerge
//!   set_phase(Landing, RebaseDoneBookmarkPending)
//!   ├─ fast_forward_bookmark(main → landed commit)   (FF-guarded; no-op if already there)
//!   │   └─ not a fast-forward? ─▶ set_phase(AwaitingHumanMerge, None) ─▶ AwaitingHumanMerge
//!   set_phase(Landing, BookmarkMovedComplete)
//!   set_phase(Merged, None) ─▶ Merged
//! ```
//!
//! # Two ways this could corrupt `main`, and how it doesn't
//!
//! **Never rewind `main` (fast-forward guard).** The bookmark move is not a
//! blind set: [`WorkspaceManager::fast_forward_bookmark`] first verifies the
//! *current* `main` commit is an ancestor of the landing target, all under one
//! hold of the `.jj/` gate. If it is not (a stale/advanced/wrong target, or a
//! concurrent lander that advanced `main` between our rebase and move — REQ-5a),
//! the move is *refused* ([`LandingError::NotFastForward`]) and the issue parks
//! at `phase:awaiting-human-merge`. `main` can only ever advance. The guard is
//! the load-bearing safety property: an interleave *fails safe* (errors) rather
//! than silently moving trunk sideways.
//!
//! **Move to the commit the rebase produced, not a re-resolved revset.** The
//! fresh-land path threads the commit id that `rebase(...)` returned — a commit
//! provably descended from the rebase's `main` — as the
//! move target, rather than re-resolving `change_revset` (which a race could
//! have advanced). On resume, where that `CommitInfo` isn't in hand, the target
//! is re-derived from the stable change id via the length-checked
//! `resolve_change`, and the FF guard still applies.
//!
//! # Idempotent resume against filesystem ground truth (REQ-15, AC-18)
//!
//! Every step is idempotent, and [`resume_from`] re-reads jj ground truth
//! before acting rather than assuming a no-op:
//!
//! - `RebaseStarted` resume re-rebases, but a change already a descendant of
//!   `main` needs no rebase (checked first), so re-running never duplicates or
//!   re-parents it.
//! - `RebaseDoneBookmarkPending` resume reads `main`'s actual commit via
//!   [`WorkspaceManager::bookmark_target`]: if `main` already points at the
//!   landing target the move already happened (advance, no re-move); otherwise
//!   it applies the FF-guarded move.
//!
//! Re-entry at any landing substate thus converges on the same terminal state.
//!
//! # The `.jj/` gate (REQ-5a, AC-24)
//!
//! Every `.jj/` read or mutation goes through [`WorkspaceManager`]'s landing
//! primitives, which take the one serializing mutex (REQ-5a) — landing's rebase
//! can never race the build pump's `workspace add`. No `jj`/`git` subprocess is
//! spawned; all graph work is `jj_api` (AC-24). There is no `unwrap`/`panic` on
//! any non-test path.

use serde_json::json;
use vetinari_error::LandingError;

use crate::events::{emit, EventLog};
use crate::state::{EventKind, Phase, PhaseSubstate, StateDb};
use crate::workspace::WorkspaceManager;

/// The name of the bookmark local-mode landing fast-forwards. The fixture and
/// the dogfood target both track trunk under `main`; kept as a constant so the
/// design layout and the code agree.
pub const MAIN_BOOKMARK: &str = "main";

/// The closed set of terminal outcomes of a local-mode landing attempt.
///
/// Exhaustive on purpose: the phase machine (P2) matches on this to decide the
/// terminal phase, and a new outcome must force every match site to be updated
/// rather than silently fall through a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandingOutcome {
    /// The change rebased cleanly and `main` was fast-forwarded to it — the
    /// issue is now at `phase:merged`.
    Merged,
    /// The rebase produced conflicts; the issue is parked at
    /// `phase:awaiting-human-merge` for a human (the Merger role is deferred).
    /// `main` was **not** moved.
    AwaitingHumanMerge,
}

/// Land the change `change_revset` resolves to onto `main`, driving the full
/// substate machine from the top (`RebaseStarted`) and persisting each step to
/// `state.db` between jj ops so a crash mid-landing is resumable (REQ-2a,
/// AC-18).
///
/// See the module docs for the state diagram. Returns [`LandingOutcome::Merged`]
/// on a clean land, or [`LandingOutcome::AwaitingHumanMerge`] if the rebase
/// conflicted (an expected, non-error outcome — a conflict is a *successful* jj
/// rebase whose result tree carries markers). Genuine jj-op failures surface as
/// [`LandingError`].
pub fn land_local(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    issue_id: &str,
    change_revset: &str,
) -> Result<LandingOutcome, LandingError> {
    resume_from(
        state,
        log,
        manager,
        issue_id,
        change_revset,
        PhaseSubstate::RebaseStarted,
    )
}

/// Drive the landing substate machine starting at `from` — the resumable entry
/// point (REQ-15, AC-18).
///
/// [`land_local`] calls this with [`PhaseSubstate::RebaseStarted`] for a fresh
/// landing; the recovery path (P2, #16) calls it with whatever substate
/// `state.db` last recorded so a crash between two jj ops re-enters the machine
/// exactly where it stopped. Every step from `RebaseDoneBookmarkPending` onward
/// is idempotent (the bookmark move is a jj no-op when `main` already points at
/// the landed change), so re-entry at any substate converges on the same
/// terminal state.
///
/// A substate outside the landing set (`RebaseStarted`,
/// `RebaseDoneBookmarkPending`, `BookmarkMovedComplete`) is not a landing
/// resume point and yields [`LandingError::SubstateInconsistent`].
pub fn resume_from(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    issue_id: &str,
    change_revset: &str,
    from: PhaseSubstate,
) -> Result<LandingOutcome, LandingError> {
    match from {
        PhaseSubstate::RebaseStarted => rebase_step(state, log, manager, issue_id, change_revset),
        PhaseSubstate::RebaseDoneBookmarkPending => {
            // Resume after a crash between the rebase and the bookmark move. The
            // rebase already committed; pick up at the FF-guarded move, reading
            // jj ground truth (main's actual position) to decide whether the
            // move already happened.
            bookmark_step(state, log, manager, issue_id, change_revset)
        }
        PhaseSubstate::BookmarkMovedComplete => {
            // Resume after a crash between the bookmark move and the terminal
            // transition. The move already happened; just finish.
            merged_step(state, log, issue_id)
        }
        other => Err(LandingError::SubstateInconsistent {
            substate: other.as_str().to_owned(),
            fs_truth: "not a landing-phase substate; cannot resume landing here".to_owned(),
        }),
    }
}

/// `RebaseStarted`: rebase the change onto `main`. A conflict parks for a human;
/// a clean rebase advances to the bookmark-move step, carrying the commit the
/// rebase *produced* as the fast-forward target.
///
/// Persists `Landing/RebaseStarted` up front so a crash mid-rebase is
/// recoverable — this is the single write of that substate, driving both the
/// fresh land (issue was `Converged`) and a resume (state.db already said
/// `RebaseStarted`), so the resume-entry arm does not re-persist it.
///
/// The rebase is idempotent on resume: a change already a descendant of `main`
/// (e.g. the rebase committed pre-crash) needs no rebase — re-parenting it would
/// be a no-op, but we skip it entirely so nothing is rewritten and its commit id
/// stays stable for the move target.
fn rebase_step(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    issue_id: &str,
    change_revset: &str,
) -> Result<LandingOutcome, LandingError> {
    set_phase(
        state,
        issue_id,
        Phase::Landing,
        Some(PhaseSubstate::RebaseStarted),
    )?;
    // If the change is already a descendant of (or equal to) `main`, the rebase
    // already happened (or was never needed): re-running it would rewrite the
    // commit for no reason. Skip it and use the change's current commit as the
    // target — this is what makes a `RebaseStarted` resume idempotent (AC-18).
    let target = if manager.is_ancestor(MAIN_BOOKMARK, change_revset)? {
        manager.resolve_change(change_revset)?
    } else {
        manager.rebase(change_revset, MAIN_BOOKMARK)?
    };
    if target.has_conflict {
        // A conflict is a *successful* jj rebase whose result tree carries
        // markers — not a `LandingError`. The Merger role (#L4) is deferred, so
        // the issue parks for a human at `phase:awaiting-human-merge` and `main`
        // is left untouched.
        set_phase(state, issue_id, Phase::AwaitingHumanMerge, None)?;
        emit_transition(
            log,
            state,
            issue_id,
            Phase::Landing,
            Phase::AwaitingHumanMerge,
            "rebase conflict — parked for human merge (Merger deferred)",
        )?;
        return Ok(LandingOutcome::AwaitingHumanMerge);
    }
    set_phase(
        state,
        issue_id,
        Phase::Landing,
        Some(PhaseSubstate::RebaseDoneBookmarkPending),
    )?;
    // Move to the commit the rebase actually produced (provably descended from
    // the rebase's `main`), not a re-resolved revset a race could have advanced.
    move_step(state, log, manager, issue_id, &target.commit_id)
}

/// `RebaseDoneBookmarkPending` resume entry: re-read jj ground truth (main's
/// actual position, REQ-15) and either advance (the move already happened) or
/// apply the FF-guarded move. The move target is re-derived from the stable
/// change id, since the rebase's `CommitInfo` isn't in hand on resume.
fn bookmark_step(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    issue_id: &str,
    change_revset: &str,
) -> Result<LandingOutcome, LandingError> {
    let target = manager.resolve_change(change_revset)?;
    move_step(state, log, manager, issue_id, &target.commit_id)
}

/// Fast-forward `main` to `target_commit`, then advance to `merged`.
///
/// Reads jj ground truth first (REQ-15): if `main` already points at the target,
/// the move happened pre-crash — advance without a second move. Otherwise apply
/// the FF-guarded move ([`WorkspaceManager::fast_forward_bookmark`]), which
/// refuses to rewind `main` — a non-fast-forward parks the issue for a human
/// rather than corrupting trunk. Idempotent, so it is safe to re-run on resume.
fn move_step(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    issue_id: &str,
    target_commit: &str,
) -> Result<LandingOutcome, LandingError> {
    let main_now = manager.bookmark_target(MAIN_BOOKMARK)?;
    if main_now.as_deref() != Some(target_commit) {
        // Not already at the target: apply the guarded move. A non-fast-forward
        // (a concurrent lander advanced `main`, or a stale target) is refused
        // and parks for a human instead of rewinding trunk.
        match manager.fast_forward_bookmark(MAIN_BOOKMARK, target_commit) {
            Ok(()) => {}
            Err(LandingError::NotFastForward {
                bookmark,
                current,
                target,
            }) => {
                set_phase(state, issue_id, Phase::AwaitingHumanMerge, None)?;
                emit_transition(
                    log,
                    state,
                    issue_id,
                    Phase::Landing,
                    Phase::AwaitingHumanMerge,
                    &format!(
                        "refusing non-fast-forward move of `{bookmark}` \
                         (`{current}` is not an ancestor of `{target}`) — \
                         parked for human merge"
                    ),
                )?;
                return Ok(LandingOutcome::AwaitingHumanMerge);
            }
            Err(other) => return Err(other),
        }
    }
    set_phase(
        state,
        issue_id,
        Phase::Landing,
        Some(PhaseSubstate::BookmarkMovedComplete),
    )?;
    merged_step(state, log, issue_id)
}

/// `BookmarkMovedComplete`: the terminal transition to `phase:merged`.
fn merged_step(
    state: &StateDb,
    log: &EventLog,
    issue_id: &str,
) -> Result<LandingOutcome, LandingError> {
    set_phase(state, issue_id, Phase::Merged, None)?;
    emit_transition(
        log,
        state,
        issue_id,
        Phase::Landing,
        Phase::Merged,
        "landed locally: rebased onto main and fast-forwarded the main bookmark",
    )?;
    Ok(LandingOutcome::Merged)
}

/// Persist a phase/substate transition, mapping the `state.db` write failure
/// into the landing error surface so the whole machine returns [`LandingError`].
fn set_phase(
    state: &StateDb,
    issue_id: &str,
    phase: Phase,
    substate: Option<PhaseSubstate>,
) -> Result<(), LandingError> {
    state
        .set_phase(issue_id, phase, substate)
        .map_err(|source| LandingError::BookmarkMoveFailed {
            bookmark: format!("state.db set_phase for `{issue_id}`"),
            source: Box::new(source),
        })
}

/// Emit a landing transition event to both `state.db` and `events.jsonl` (AC-9),
/// mapping the write failure into the landing error surface.
fn emit_transition(
    log: &EventLog,
    state: &StateDb,
    issue_id: &str,
    from: Phase,
    to: Phase,
    reason: &str,
) -> Result<(), LandingError> {
    emit(
        state,
        log,
        EventKind::Transition,
        Some(issue_id),
        None,
        &json!({
            "from_phase": from.as_str(),
            "to_phase": to.as_str(),
            "reason": reason,
        }),
    )
    .map(|_id| ())
    .map_err(|source| LandingError::BookmarkMoveFailed {
        bookmark: format!("emit landing transition for `{issue_id}`"),
        source: Box::new(source),
    })
}
