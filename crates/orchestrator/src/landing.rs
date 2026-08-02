//! Mode-gated landing (REQ-17). The **local** path rebases a converged issue's
//! change onto `main` and fast-forwards the `main` bookmark to it (REQ-2a,
//! AC-11a, AC-18); the **remote** path (selected when crosslink's
//! `tracker_remote` is set) instead pushes a per-issue branch and opens a GitHub
//! PR → `phase:pr-open` (see the "Remote-mode landing" section below). This
//! module header documents the local machine; the remote machine is documented
//! at [`land_remote`].
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

/// The closed set of terminal outcomes of a landing attempt (local or remote).
///
/// Exhaustive on purpose: the phase machine (P2) matches on this to decide the
/// terminal phase, and a new outcome must force every match site to be updated
/// rather than silently fall through a wildcard.
///
/// Not `Copy`: [`PrOpen`](LandingOutcome::PrOpen) carries the PR url, so the
/// outcome is `Clone` but moved by value like any other owned enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandingOutcome {
    /// The change rebased cleanly and `main` was fast-forwarded to it — the
    /// issue is now at `phase:merged` (local mode).
    Merged,
    /// The issue's branch was pushed and a GitHub PR was opened — the issue is
    /// now at `phase:pr-open` (remote mode, REQ-17). `main` was **not** moved.
    PrOpen {
        /// The URL of the opened pull request, recorded on the transition.
        url: String,
    },
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

// ============================================================================
// Remote-mode landing (REQ-17 remote path, REQ-2a, REQ-1a)
// ============================================================================
//
// When crosslink's `tracker_remote` is SET, landing does NOT fast-forward
// `main`. Instead the orchestrator points a per-issue branch (`vdd/<id>-<slug>`,
// design Q2) at the reviewed change, `jj git push`es it to the remote, and opens
// a GitHub pull request → `phase:pr-open`. The substate machine persists each
// step to `state.db` between the ops so a crash mid-landing is recoverable
// (REQ-2a):
//
// ```text
//   set_phase(Landing, PushStarted)
//   ├─ point_bookmark(branch → reviewed change)   (idempotent)
//   ├─ git_push(remote, branch)
//   set_phase(Landing, PushDonePrPending)
//   ├─ PrOpener::open_pr(...) -> url               (the GitHub side, seam-isolated)
//   set_phase(Landing, PrCreated)
//   set_phase(PrOpen, None) ─▶ PrOpen { url }
// ```
//
// GitHub PR creation is behind the [`PrOpener`] seam so the state machine + the
// branch push are testable WITHOUT a live GitHub: a test drives `land_remote`
// with a fake opener while the real push hits a local bare-git remote.

/// The GitHub coordinates of one pull request to open, handed to a [`PrOpener`].
///
/// Borrows every field: the caller ([`land_remote`]) owns the branch name,
/// title, and body for the duration of the call.
#[derive(Debug, Clone, Copy)]
pub struct PrRequest<'a> {
    /// The head branch the PR is opened from (`vdd/<id>-<slug>`), already pushed.
    pub head: &'a str,
    /// The base branch the PR merges into (typically `main`).
    pub base: &'a str,
    /// PR title — the reviewed change's description first line.
    pub title: &'a str,
    /// PR body — sourced from the worker's `_orchestrator/result.md`.
    pub body: &'a str,
}

/// The seam that isolates GitHub PR creation from the landing state machine
/// (REQ-1a). Creating a real PR is neither deterministic nor CI-friendly, so the
/// machine depends on this trait rather than on `octocrab` directly: production
/// uses [`OctocrabPrOpener`]; tests use a fake that records the request and
/// returns a canned URL, exercising the push + substate machine offline.
pub trait PrOpener {
    /// Open a pull request for `req`, returning its URL on success. A failure is
    /// surfaced as [`LandingError::PrOpenFailed`] (or
    /// [`LandingError::GhAuthMissing`] when no token is configured).
    fn open_pr(&self, req: &PrRequest<'_>) -> Result<String, LandingError>;

    /// Look up an **already-open** pull request whose head branch is `head`,
    /// returning its URL if one exists (else `None`). This is what makes PR
    /// creation idempotent on resume (REQ-2a crash-safety): [`push_step`] persists
    /// `PushDonePrPending` *before* the PR is created, so a crash after GitHub
    /// created the PR but before the substate advanced would, on a naive resume,
    /// call [`open_pr`](PrOpener::open_pr) again — which GitHub rejects with a 422
    /// "a pull request already exists", stranding the issue. Instead the machine
    /// first asks here; a `Some(url)` is adopted as success (no duplicate, no
    /// re-push). A `PrCreated` resume likewise re-derives the url from here.
    ///
    /// A lookup failure is surfaced as [`LandingError::PrOpenFailed`].
    fn find_open_pr(&self, head: &str) -> Result<Option<String>, LandingError>;
}

/// The inputs a remote-mode landing needs, threaded through the substate machine.
#[derive(Debug, Clone, Copy)]
pub struct RemoteLanding<'a> {
    /// The issue's `state.db` key.
    pub issue_id: &'a str,
    /// Revset resolving to the reviewed change to land.
    pub change_revset: &'a str,
    /// Git remote to push to (crosslink's `tracker_remote`, e.g. `origin`).
    pub remote: &'a str,
    /// The per-issue branch to push (`vdd/<id>-<slug>`, from [`branch_name`]).
    pub branch: &'a str,
    /// The PR base branch (typically [`MAIN_BOOKMARK`]).
    pub base: &'a str,
    /// PR title (the change description's first line).
    pub title: &'a str,
    /// PR body (the worker's `_orchestrator/result.md`).
    pub body: &'a str,
}

/// The per-issue branch name for landing, `vdd/<id>-<slug>` (design Q2).
///
/// The slug is derived from the issue title: lowercased, every non-alphanumeric
/// run folded to a single `-`, trimmed, and capped at ~40 chars on a `-`
/// (word) boundary. Example: id `42`, title "Add batch retry logic for sync" →
/// `vdd/42-add-batch-retry-logic-for-sync`.
pub fn branch_name(issue_id: &str, title: &str) -> String {
    let id = slugify(issue_id, usize::MAX);
    let id = if id.is_empty() {
        "issue".to_owned()
    } else {
        id
    };
    let slug = slugify(title, 40);
    if slug.is_empty() {
        format!("vdd/{id}")
    } else {
        format!("vdd/{id}-{slug}")
    }
}

/// Lowercase `raw`, fold each non-alphanumeric run to a single `-`, trim, and
/// cap the result at `max_len` chars on a `-` boundary (never mid-word). Shared
/// by the id and title segments of [`branch_name`].
fn slugify(raw: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_len.saturating_add(1)));
    let mut prev_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.len() <= max_len {
        return trimmed.to_owned();
    }
    // Cap at a word boundary: cut at the last `-` at or before max_len so the
    // slug never ends mid-word, then re-trim any trailing dash.
    let head = &trimmed[..max_len];
    let cut = head.rfind('-').map(|i| &head[..i]).unwrap_or(head);
    cut.trim_matches('-').to_owned()
}

/// Land the reviewed change in **remote mode** (REQ-17): push its branch and
/// open a GitHub PR → `phase:pr-open`. Drives the substate machine from the top
/// (`PushStarted`), persisting each step to `state.db` between ops so a crash
/// mid-landing is resumable (REQ-2a).
///
/// The `opener` is the [`PrOpener`] seam — an [`OctocrabPrOpener`] in production,
/// a fake in tests — so the push + substate machine run without a live GitHub.
/// Returns [`LandingOutcome::PrOpen`] carrying the PR url on success.
pub fn land_remote(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    opener: &dyn PrOpener,
    params: &RemoteLanding<'_>,
) -> Result<LandingOutcome, LandingError> {
    resume_remote_from(
        state,
        log,
        manager,
        opener,
        params,
        PhaseSubstate::PushStarted,
    )
}

/// Drive the remote-landing substate machine starting at `from` — the resumable
/// entry point (REQ-15, AC-18), mirroring [`resume_from`] for the local path.
///
/// [`land_remote`] enters at [`PhaseSubstate::PushStarted`]; the recovery path
/// (P2, #16) re-enters at whatever substate `state.db` last recorded:
///
/// - `PushStarted` — re-point the branch + re-push (both idempotent), then the
///   idempotent PR step.
/// - `PushDonePrPending` — the branch is pushed; run the idempotent PR step,
///   which adopts an already-open PR (via [`PrOpener::find_open_pr`]) rather
///   than re-creating it (a naive re-create is a GitHub 422 — the F2 hazard).
/// - `PrCreated` — GitHub already has the PR; re-derive its url via
///   [`PrOpener::find_open_pr`] and finish the terminal transition to
///   `phase:pr-open`. No re-create, no re-push.
///
/// Any non-remote substate is rejected as [`LandingError::SubstateInconsistent`].
pub fn resume_remote_from(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    opener: &dyn PrOpener,
    params: &RemoteLanding<'_>,
    from: PhaseSubstate,
) -> Result<LandingOutcome, LandingError> {
    match from {
        PhaseSubstate::PushStarted => push_step(state, log, manager, opener, params),
        PhaseSubstate::PushDonePrPending => pr_step(state, log, manager, opener, params),
        PhaseSubstate::PrCreated => {
            // The PR was created (state.db recorded PrCreated) but the terminal
            // transition to pr-open did not commit. Re-derive the existing PR's
            // url from GitHub and finish — never a second create.
            let url = opener.find_open_pr(params.branch)?.ok_or_else(|| {
                LandingError::SubstateInconsistent {
                    substate: PhaseSubstate::PrCreated.as_str().to_owned(),
                    fs_truth: format!(
                        "state.db says the PR for head `{}` was created, but no open PR exists \
                         for it on the remote — cannot re-derive its url",
                        params.branch
                    ),
                }
            })?;
            complete_pr_open(state, log, manager, params.issue_id, params.branch, url)
        }
        other => Err(LandingError::SubstateInconsistent {
            substate: other.as_str().to_owned(),
            fs_truth: "not a resumable remote-landing substate".to_owned(),
        }),
    }
}

/// `PushStarted`: point the issue branch at the reviewed change and push it to
/// the remote, then advance to PR creation. Both the bookmark move and (a
/// re-run) push are idempotent, so a `PushStarted` resume converges.
fn push_step(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    opener: &dyn PrOpener,
    params: &RemoteLanding<'_>,
) -> Result<LandingOutcome, LandingError> {
    set_phase(
        state,
        params.issue_id,
        Phase::Landing,
        Some(PhaseSubstate::PushStarted),
    )?;
    // Point the per-issue branch at the reviewed change (create-or-move), then
    // push it. Unlike the local path there is no fast-forward guard: this is the
    // orchestrator's own per-issue branch, not shared trunk.
    manager.point_bookmark(params.branch, params.change_revset)?;
    manager.git_push(params.remote, params.branch)?;
    set_phase(
        state,
        params.issue_id,
        Phase::Landing,
        Some(PhaseSubstate::PushDonePrPending),
    )?;
    pr_step(state, log, manager, opener, params)
}

/// `PushDonePrPending`: the branch is pushed; open the GitHub PR through the
/// seam, record its url, and finish. Re-entered on resume after a crash between
/// the push and the PR create.
///
/// **Idempotent PR creation (F2).** `state.db` records `PushDonePrPending`
/// *before* the create, so a crash after GitHub created the PR but before the
/// substate advanced would re-enter here. Re-creating blindly is a GitHub 422
/// ("a pull request already exists") that strands the issue forever, so this
/// first asks [`PrOpener::find_open_pr`] for an existing open PR on the head
/// branch and **adopts** it as success; only when none exists is a fresh PR
/// created. After F1+F2 a crash anywhere in the create window self-heals to
/// `pr_created` with the correct url — no duplicate PR, no double-push.
fn pr_step(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    opener: &dyn PrOpener,
    params: &RemoteLanding<'_>,
) -> Result<LandingOutcome, LandingError> {
    let url = match opener.find_open_pr(params.branch)? {
        Some(existing) => existing,
        None => opener.open_pr(&PrRequest {
            head: params.branch,
            base: params.base,
            title: params.title,
            body: params.body,
        })?,
    };
    set_phase(
        state,
        params.issue_id,
        Phase::Landing,
        Some(PhaseSubstate::PrCreated),
    )?;
    complete_pr_open(state, log, manager, params.issue_id, params.branch, url)
}

/// The terminal remote-landing transition: `Landing → PrOpen`, recording the PR
/// `url` on the event (durable in the trail even though `state.db` has no url
/// column), then reaping the local `vdd/<id>-<slug>` bookmark (F5).
///
/// Shared by the fresh [`pr_step`] and the `PrCreated` resume, so both finish
/// identically. The bookmark reap forgets only the **local** pointer — the
/// branch already lives on the remote as the PR head — so the repository does
/// not accrue one dead bookmark per landed issue. It is best-effort: the PR is
/// already open, so a reap failure must not fail the landing (it would only
/// leave the cosmetic local bookmark behind).
fn complete_pr_open(
    state: &StateDb,
    log: &EventLog,
    manager: &WorkspaceManager,
    issue_id: &str,
    branch: &str,
    url: String,
) -> Result<LandingOutcome, LandingError> {
    set_phase(state, issue_id, Phase::PrOpen, None)?;
    emit_pr_open(log, state, issue_id, branch, &url)?;
    let _ = manager.forget_bookmark(branch);
    Ok(LandingOutcome::PrOpen { url })
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

/// Emit the terminal remote-landing transition (`landing → pr-open`) carrying
/// the pushed `branch` and the opened PR `url`, so the trail records where the
/// change went even though `state.db` holds no url column.
fn emit_pr_open(
    log: &EventLog,
    state: &StateDb,
    issue_id: &str,
    branch: &str,
    url: &str,
) -> Result<(), LandingError> {
    emit(
        state,
        log,
        EventKind::Transition,
        Some(issue_id),
        None,
        &json!({
            "from_phase": Phase::Landing.as_str(),
            "to_phase": Phase::PrOpen.as_str(),
            "reason": "landed remotely: pushed the issue branch and opened a GitHub PR",
            "branch": branch,
            "pr_url": url,
        }),
    )
    .map(|_id| ())
    .map_err(|source| LandingError::BookmarkMoveFailed {
        bookmark: format!("emit pr-open transition for `{issue_id}`"),
        source: Box::new(source),
    })
}

// ============================================================================
// OctocrabPrOpener — the production PrOpener (REQ-1a)
// ============================================================================

/// The production [`PrOpener`]: opens a GitHub PR through the `octocrab` library
/// (REQ-1a — never a `gh` subprocess, AC-24).
///
/// Holds the repository coordinates (`owner`/`repo`) and a personal-access
/// token. The token is read from `GH_TOKEN` (falling back to `GITHUB_TOKEN`) by
/// [`from_env`](OctocrabPrOpener::from_env). Because `octocrab` is async over
/// hyper, [`open_pr`](PrOpener::open_pr) drives the single PR-create future to
/// completion on a private current-thread tokio runtime — no async runtime is
/// threaded through the rest of the (synchronous) orchestrator.
pub struct OctocrabPrOpener {
    /// GitHub repository owner (user or org).
    owner: String,
    /// GitHub repository name.
    repo: String,
    /// Personal access token used to authenticate the PR create.
    token: String,
}

impl OctocrabPrOpener {
    /// Build an opener for `owner`/`repo`, reading the token from `GH_TOKEN`
    /// (then `GITHUB_TOKEN`). A missing token is [`LandingError::GhAuthMissing`]
    /// — remote-mode landing cannot open a PR unauthenticated (AC-12).
    pub fn from_env(
        owner: impl Into<String>,
        repo: impl Into<String>,
    ) -> Result<Self, LandingError> {
        let token = std::env::var("GH_TOKEN")
            .or_else(|_| std::env::var("GITHUB_TOKEN"))
            .map_err(|_| LandingError::GhAuthMissing)?;
        Ok(OctocrabPrOpener {
            owner: owner.into(),
            repo: repo.into(),
            token,
        })
    }

    /// Build an opener resolving the repository slug from the `GITHUB_REPOSITORY`
    /// environment variable (`owner/repo`, the conventional GitHub Actions form)
    /// and the token via [`from_env`](OctocrabPrOpener::from_env). An absent or
    /// malformed slug is [`LandingError::GhAuthMissing`] — remote mode is not
    /// configured for PR creation.
    pub fn from_github_env() -> Result<Self, LandingError> {
        let slug = std::env::var("GITHUB_REPOSITORY").map_err(|_| LandingError::GhAuthMissing)?;
        let (owner, repo) = slug
            .split_once('/')
            .filter(|(o, r)| !o.is_empty() && !r.is_empty())
            .ok_or(LandingError::GhAuthMissing)?;
        Self::from_env(owner.to_owned(), repo.to_owned())
    }

    /// Build an opener whose `owner`/`repo` are derived from the **same** git
    /// remote the branch is pushed to (F3), so the push target and the PR target
    /// cannot diverge by construction.
    ///
    /// The `remote`'s URL is read from git config (via the `.jj/` gate) and
    /// parsed with [`parse_owner_repo`], handling both the
    /// `git@github.com:owner/repo.git` and `https://github.com/owner/repo(.git)`
    /// forms. When the URL is absent or not a recognizable GitHub URL (e.g. a
    /// local bare-repo remote in a test, or a self-hosted host), it falls back to
    /// [`from_github_env`](OctocrabPrOpener::from_github_env) — the prior
    /// `GITHUB_REPOSITORY` behavior — so nothing regresses. The token still comes
    /// from `GH_TOKEN`/`GITHUB_TOKEN`; a missing token is
    /// [`LandingError::GhAuthMissing`].
    pub fn for_remote(manager: &WorkspaceManager, remote: &str) -> Result<Self, LandingError> {
        if let Some(url) = manager.remote_url(remote)? {
            if let Some((owner, repo)) = parse_owner_repo(&url) {
                return Self::from_env(owner, repo);
            }
        }
        // No URL, or not a GitHub URL we can parse — fall back to the env slug so
        // behavior is never worse than before F3.
        Self::from_github_env()
    }
}

/// Parse a GitHub `owner/repo` out of a git remote URL, or `None` if it is not a
/// recognizable GitHub-style URL.
///
/// Handles the two forms git remotes take:
/// - SCP-like SSH: `git@github.com:owner/repo.git`
/// - HTTP(S): `https://github.com/owner/repo(.git)` (any host; the host segment
///   is dropped — the `owner/repo` tail is what matters)
///
/// A trailing `.git` and any trailing `/` are stripped. Returns `None` for a
/// URL with no `owner/repo` tail (e.g. a bare local path like
/// `/tmp/xyz/origin.git`), so the caller falls back to the env slug.
fn parse_owner_repo(url: &str) -> Option<(String, String)> {
    let url = url.trim();
    // Take everything after the host: the SSH form separates host from path with
    // `:`, the URL form with the first `/` after the host. Normalize both to the
    // `owner/repo` path tail.
    let path = if let Some((_scheme_host, rest)) = url.split_once("://") {
        // `host/owner/repo...` — drop the host segment.
        rest.split_once('/').map(|(_host, p)| p)?
    } else if let Some((_userhost, p)) = url.split_once(':') {
        // `git@host:owner/repo...` (SCP-like).
        p
    } else {
        return None;
    };
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let (owner, repo) = path.split_once('/')?;
    // `repo` must be a single segment (no further `/`) and both non-empty.
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return None;
    }
    Some((owner.to_owned(), repo.to_owned()))
}

impl OctocrabPrOpener {
    /// Build a private current-thread tokio runtime + an authenticated octocrab
    /// client — the shared setup for both PR ops so the orchestrator stays
    /// synchronous without threading a runtime through it. `head` labels any
    /// failure as [`LandingError::PrOpenFailed`].
    fn runtime_and_client(
        &self,
        head: &str,
    ) -> Result<(tokio::runtime::Runtime, octocrab::Octocrab), LandingError> {
        let fail = |source: Box<dyn std::error::Error + Send + Sync + 'static>| {
            LandingError::PrOpenFailed {
                head: head.to_owned(),
                source,
            }
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| fail(Box::new(e)))?;
        let client = octocrab::Octocrab::builder()
            .personal_token(self.token.clone())
            .build()
            .map_err(|e| fail(Box::new(e)))?;
        Ok((runtime, client))
    }

    /// List open PRs whose head branch is `head` and return the first's url, if
    /// any — the async core shared by [`find_open_pr`](PrOpener::find_open_pr)
    /// and `open_pr`'s idempotency backstop. Filters server-side by
    /// `<owner>:<head>` and re-checks the ref client-side so a partial match
    /// cannot be adopted.
    async fn find_open_pr_on(
        &self,
        client: &octocrab::Octocrab,
        head: &str,
    ) -> Result<Option<String>, LandingError> {
        let page = client
            .pulls(&self.owner, &self.repo)
            .list()
            .state(octocrab::params::State::Open)
            .head(format!("{}:{}", self.owner, head))
            .per_page(10)
            .send()
            .await
            .map_err(|e| LandingError::PrOpenFailed {
                head: head.to_owned(),
                source: Box::new(e),
            })?;
        Ok(page
            .items
            .into_iter()
            .find(|pr| pr.head.ref_field == head)
            .and_then(|pr| pr.html_url.map(|u| u.to_string())))
    }
}

impl PrOpener for OctocrabPrOpener {
    fn open_pr(&self, req: &PrRequest<'_>) -> Result<String, LandingError> {
        let (runtime, client) = self.runtime_and_client(req.head)?;
        runtime.block_on(async {
            match client
                .pulls(&self.owner, &self.repo)
                .create(req.title, req.head, req.base)
                .body(req.body)
                .send()
                .await
            {
                Ok(pr) => Ok(pr.html_url.map(|u| u.to_string()).unwrap_or_else(|| {
                    format!("https://github.com/{}/{}/pull/new", self.owner, self.repo)
                })),
                // Idempotency backstop (F2): GitHub rejects a duplicate create
                // with a 422 "a pull request already exists". If a PR for this
                // head already exists (a create raced our pre-check, or the prior
                // attempt created it), adopt it as success instead of stranding
                // the issue. Only when no open PR is found is the create error
                // surfaced.
                Err(create_err) => match self.find_open_pr_on(&client, req.head).await {
                    Ok(Some(url)) => Ok(url),
                    _ => Err(LandingError::PrOpenFailed {
                        head: req.head.to_owned(),
                        source: Box::new(create_err),
                    }),
                },
            }
        })
    }

    fn find_open_pr(&self, head: &str) -> Result<Option<String>, LandingError> {
        let (runtime, client) = self.runtime_and_client(head)?;
        runtime.block_on(async { self.find_open_pr_on(&client, head).await })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_name_matches_design_q2_example() {
        // design Q2: issue #42 "Add batch retry logic for sync" →
        // vdd/42-add-batch-retry-logic-for-sync.
        assert_eq!(
            branch_name("42", "Add batch retry logic for sync"),
            "vdd/42-add-batch-retry-logic-for-sync"
        );
    }

    #[test]
    fn branch_name_lowercases_folds_and_trims() {
        // Punctuation and case fold to `-`; runs collapse; leading/trailing trim.
        assert_eq!(
            branch_name("L3", "  Fix: the WIDGET!! (v2) "),
            "vdd/l3-fix-the-widget-v2"
        );
    }

    #[test]
    fn slugify_caps_at_word_boundary() {
        // A long title is capped at ~40 chars, never mid-word (cut at a `-`).
        let slug = slugify(
            "one two three four five six seven eight nine ten eleven",
            40,
        );
        assert!(slug.len() <= 40, "slug `{slug}` exceeds the cap");
        assert!(
            !slug.ends_with('-'),
            "slug must not end on a dash: `{slug}`"
        );
        // Every retained token is whole (present in the source, in order).
        assert_eq!(slug, "one-two-three-four-five-six-seven-eight");
    }

    #[test]
    fn branch_name_folds_empty_segments_to_sentinels() {
        // An all-punctuation id folds to the `issue` sentinel; an empty title
        // yields just `vdd/<id>` (no trailing dash).
        assert_eq!(branch_name("###", "!!!"), "vdd/issue");
        assert_eq!(branch_name("7", "   "), "vdd/7");
    }

    #[test]
    fn parse_owner_repo_handles_ssh_and_https_forms() {
        // SCP-like SSH, with and without `.git`.
        assert_eq!(
            parse_owner_repo("git@github.com:acme/hello.git"),
            Some(("acme".to_owned(), "hello".to_owned()))
        );
        assert_eq!(
            parse_owner_repo("git@github.com:acme/hello"),
            Some(("acme".to_owned(), "hello".to_owned()))
        );
        // HTTPS, with and without `.git` and a trailing slash.
        assert_eq!(
            parse_owner_repo("https://github.com/acme/hello.git"),
            Some(("acme".to_owned(), "hello".to_owned()))
        );
        assert_eq!(
            parse_owner_repo("https://github.com/acme/hello/"),
            Some(("acme".to_owned(), "hello".to_owned()))
        );
        // A bare local path (a test's bare-repo remote) has no owner/repo tail.
        assert_eq!(parse_owner_repo("/tmp/xyz/origin.git"), None);
        // A URL with no repo segment.
        assert_eq!(parse_owner_repo("https://github.com/acme"), None);
    }

    #[test]
    fn octocrab_opener_from_env_requires_a_token() {
        // With neither GH_TOKEN nor GITHUB_TOKEN set, construction is
        // GhAuthMissing. (Serialized single-threaded test; restores the env.)
        let saved = (
            std::env::var("GH_TOKEN").ok(),
            std::env::var("GITHUB_TOKEN").ok(),
        );
        std::env::remove_var("GH_TOKEN");
        std::env::remove_var("GITHUB_TOKEN");
        // `OctocrabPrOpener` deliberately isn't `Debug` (it holds a token), so
        // match the result rather than `expect_err`.
        assert!(
            matches!(
                OctocrabPrOpener::from_env("acme", "hello"),
                Err(LandingError::GhAuthMissing)
            ),
            "no token must be GhAuthMissing"
        );
        // Restore whatever the environment had.
        if let Some(v) = saved.0 {
            std::env::set_var("GH_TOKEN", v);
        }
        if let Some(v) = saved.1 {
            std::env::set_var("GITHUB_TOKEN", v);
        }
    }
}
