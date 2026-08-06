//! Fixture-backed local-mode landing tests (REQ-17 local path, REQ-2a, AC-11a,
//! AC-18).
//!
//! These drive [`orchestrator::landing::land_local`] (and its resumable entry
//! point [`resume_from`]) against a *real* jj repository — the `hello` dogfood
//! fixture stood up by [`common::build_fixture`]. Every `.jj/` op runs through
//! the [`WorkspaceManager`] gate (REQ-5a); no `jj`/`git` subprocess is used from
//! the orchestrator side (AC-24) — the only shell-outs here are test-support
//! (running the committed worker script and reading the jj log).
//!
//! Covered:
//! - **Happy (AC-11a landing):** a committed change on top of `main` lands —
//!   `main` fast-forwards to the worker's change, `state.db` reads
//!   `phase:merged`, and the intermediate substates were persisted.
//! - **Conflict:** a change whose rebase onto `main` conflicts parks the issue
//!   at `phase:awaiting-human-merge` and leaves `main` untouched.
//! - **Substate resume (AC-18):** re-entering the machine at
//!   `rebase_done_bookmark_pending` completes the move idempotently to
//!   `phase:merged`.
//! - **Fast-forward-only (no rewind):** a landing target that is not a
//!   fast-forward of `main` (main advanced to an unrelated commit) is rejected
//!   and `main` is neither moved nor rewound.
//! - **Re-rebase idempotency:** resuming from `rebase_started` after the rebase
//!   already completed converges to `phase:merged` without duplicating the
//!   change.
//! - **Resume reads ground truth (REQ-15):** resuming from
//!   `rebase_done_bookmark_pending` when the move already happened advances to
//!   `phase:merged` without a second move.

mod common;

use std::path::Path;
use std::process::Command;

use common::{build_fixture, fake_implementer, Fixture};
use orchestrator::events::{EventLog, ORCHESTRATOR_DIR};
use orchestrator::landing::{land_local, resume_from, LandingOutcome, MAIN_BOOKMARK};
use orchestrator::state::{IssueRow, Phase, PhaseSubstate, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_error::LandingError;

/// Open a fresh `state.db` + `events.jsonl` pair under the fixture's
/// `.orchestrator/` and seed one issue at `phase:converged` (the phase landing
/// starts from). Returns the string issue id used throughout.
fn seed(fx: &Fixture) -> (StateDb, EventLog, String) {
    let orch = fx.root.join(ORCHESTRATOR_DIR);
    let state = StateDb::open(orch.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orch).expect("open events.jsonl");
    let issue_id = fx.issue_id.to_string();
    state
        .upsert_issue(&IssueRow::new(&issue_id, Phase::Converged))
        .expect("seed converged issue");
    (state, log, issue_id)
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

/// The commit `MAIN_BOOKMARK` points at, via the manager gate (`None` if absent).
fn main_target(manager: &WorkspaceManager) -> Option<String> {
    manager
        .bookmark_target(MAIN_BOOKMARK)
        .expect("read main bookmark target")
}

/// AC-11a landing happy path: a worker's committed change on top of `main`
/// lands. `main` fast-forwards to the change, the issue reads `phase:merged`,
/// and the machine passed through the recorded substates.
#[test]
fn land_local_fast_forwards_main_and_reaches_merged() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);

    // The worker commits its change on `@` (a child of `main`) via `jj describe`.
    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);

    // Precondition: `main` is NOT yet at the worker's change.
    let main_before = main_target(&manager).expect("fixture creates a main bookmark");
    let landed = manager
        .resolve_change(&change)
        .expect("resolve landed change");
    assert_ne!(
        main_before, landed.commit_id,
        "precondition: main must not already point at the worker's change"
    );

    let outcome =
        land_local(&state, &log, &manager, &issue_id, &change).expect("landing must succeed");
    assert_eq!(outcome, LandingOutcome::Merged, "a clean rebase must merge");

    // main moved to the landed change (fast-forward), read via bookmark_list.
    let main_after = main_target(&manager).expect("main still exists");
    let landed_after = manager.resolve_change(&change).expect("resolve after land");
    assert_eq!(
        main_after, landed_after.commit_id,
        "main must fast-forward to the landed change"
    );
    assert!(
        !landed_after.has_conflict,
        "a merged change must be conflict-free"
    );

    // state.db reads phase:merged with the substate cleared.
    let issue = state.get_issue(&issue_id).unwrap().unwrap();
    assert_eq!(issue.phase, Phase::Merged);
    assert_eq!(issue.phase_substate, None, "merged clears the substate");
}

/// Conflict path: a change whose rebase onto `main` produces conflicts surfaces
/// [`LandingOutcome::RebaseConflict`] (so the pump can dispatch a Merger, REQ-19),
/// moves the issue to the `Landing/merging` substate, and leaves `main`
/// untouched. (The pump-level Merger dispatch + retry is covered in
/// `pump_merger.rs`; `land_local` on its own only detects the conflict.)
///
/// A real conflict is staged by having `main` advance the *same* file the
/// worker's change edits, to a different content, so rebasing the worker change
/// onto the new `main` cannot apply cleanly.
#[test]
fn land_local_conflict_surfaces_rebase_conflict_and_leaves_main() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);

    // The worker edits src/lib.rs (appends say_hi) and commits on `@`.
    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);

    // Advance `main` with a CONFLICTING edit to the *same* file: create a new
    // change on main that appends different content to src/lib.rs, then move the
    // main bookmark to it. Now the worker's change (a sibling off the old main)
    // rebased onto the new main touches the same trailing region differently.
    run(
        "jj",
        &["new", "main", "-m", "conflicting main edit"],
        &fx.root,
    );
    let lib = fx.root.join("src/lib.rs");
    let mut src = std::fs::read_to_string(&lib).expect("read lib.rs");
    src.push_str("\n// conflicting trailing edit on main\npub const MAIN_MARK: u8 = 1;\n");
    std::fs::write(&lib, src).expect("write conflicting main edit");
    let conflicting_main = wc_change_id(&fx.root);
    run(
        "jj",
        &["bookmark", "set", MAIN_BOOKMARK, "-r", "@"],
        &fx.root,
    );

    let main_before = main_target(&manager).expect("main exists");

    let outcome = land_local(&state, &log, &manager, &issue_id, &change)
        .expect("a rebase conflict is not an error");
    assert!(
        matches!(outcome, LandingOutcome::RebaseConflict { .. }),
        "a conflicting rebase must surface RebaseConflict for the Merger, got {outcome:?}"
    );

    // main was NOT moved — it still points where it did before landing.
    let main_after = main_target(&manager).expect("main still exists");
    assert_eq!(
        main_after, main_before,
        "a conflict must leave the main bookmark untouched"
    );
    // And it is still the conflicting-main change, not the worker's change.
    let cm = manager
        .resolve_change(&conflicting_main)
        .expect("resolve cm");
    assert_eq!(
        main_after, cm.commit_id,
        "main stayed at the conflicting edit"
    );

    // The issue moved to the crash-safe `Landing/merging` substate (the pump
    // takes over from here to dispatch the Merger).
    let issue = state.get_issue(&issue_id).unwrap().unwrap();
    assert_eq!(issue.phase, Phase::Landing);
    assert_eq!(issue.phase_substate.as_deref(), Some("merging"));
}

/// AC-18 resume: simulate a crash between the rebase and the bookmark move —
/// `state.db` reads `rebase_done_bookmark_pending` — and re-enter the machine
/// there. It must complete the (idempotent) move to `phase:merged`.
#[test]
fn resume_from_bookmark_pending_completes_to_merged() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);

    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);

    // Reconstruct the pre-crash state: the rebase already ran (the worker's
    // change is a child of main here, so the rebase is a no-op parent-wise) and
    // the substate was persisted as `rebase_done_bookmark_pending`, but the
    // bookmark move had not yet happened.
    manager
        .rebase(&change, MAIN_BOOKMARK)
        .expect("stage: rebase step already completed pre-crash");
    state
        .set_phase(
            &issue_id,
            Phase::Landing,
            Some(PhaseSubstate::RebaseDoneBookmarkPending),
        )
        .expect("persist the crashed-at substate");

    let main_before = main_target(&manager).expect("main exists");
    let landed = manager.resolve_change(&change).expect("resolve change");
    assert_ne!(
        main_before, landed.commit_id,
        "precondition: the bookmark move had not happened before resume"
    );

    // Resume from the persisted substate — must complete, not restart the rebase.
    let outcome = resume_from(
        &state,
        &log,
        &manager,
        &issue_id,
        &change,
        PhaseSubstate::RebaseDoneBookmarkPending,
    )
    .expect("resume must complete");
    assert_eq!(outcome, LandingOutcome::Merged);

    let main_after = main_target(&manager).expect("main exists");
    let landed_after = manager.resolve_change(&change).expect("resolve after");
    assert_eq!(
        main_after, landed_after.commit_id,
        "resume must complete the fast-forward"
    );

    // Running the resume again is idempotent: the bookmark is already at the
    // change, so a second move is a jj no-op and the terminal state is stable.
    let outcome2 = resume_from(
        &state,
        &log,
        &manager,
        &issue_id,
        &change,
        PhaseSubstate::RebaseDoneBookmarkPending,
    )
    .expect("second resume is a no-op that still reaches merged");
    assert_eq!(outcome2, LandingOutcome::Merged);
    assert_eq!(
        main_target(&manager),
        Some(landed_after.commit_id),
        "idempotent: main is unchanged by the repeated resume"
    );
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::Merged
    );
}

/// Fast-forward-only guard (finding #1): a landing target that is **not** a
/// fast-forward of the current `main` must be REJECTED, and `main` must be left
/// exactly where it was — never moved sideways or rewound.
///
/// Staged via the resume path: the rebase completed pre-crash (the worker's
/// change is a child of the *old* main), state.db says
/// `rebase_done_bookmark_pending`, then `main` advances to an **unrelated**
/// commit (a sibling off the baseline, not descended from and not an ancestor
/// of the worker's change). Resuming re-derives the target (the worker's change)
/// and finds the now-current `main` is not its ancestor → the move is refused
/// and the issue parks for a human, with `main` untouched.
#[test]
fn resume_rejects_non_fast_forward_and_leaves_main_unmoved() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);

    // Worker commits its change as a child of the old main.
    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);

    // Rebase already ran pre-crash (worker change is a child of main, so it's a
    // no-op parent-wise); persist the crashed-at substate.
    manager
        .rebase(&change, MAIN_BOOKMARK)
        .expect("stage: rebase step completed pre-crash");
    state
        .set_phase(
            &issue_id,
            Phase::Landing,
            Some(PhaseSubstate::RebaseDoneBookmarkPending),
        )
        .expect("persist crashed-at substate");

    // Now advance `main` to an UNRELATED commit: a fresh change off the baseline
    // (main-) that does not touch the worker's change at all. The worker's
    // change is NOT a descendant of this new main, so moving `main` to it would
    // be a non-fast-forward (it would rewind/relocate trunk).
    run(
        "jj",
        &["new", "main-", "-m", "unrelated advance on main"],
        &fx.root,
    );
    let lib = fx.root.join("src/lib.rs");
    let mut src = std::fs::read_to_string(&lib).expect("read lib.rs");
    src.push_str("\n// unrelated advance\npub const UNRELATED: u8 = 7;\n");
    std::fs::write(&lib, src).expect("write unrelated edit");
    let unrelated = wc_change_id(&fx.root);
    // jj itself refuses a non-fast-forward bookmark move; force it here purely to
    // *stage* the corrupted-precondition the orchestrator's guard must catch.
    run(
        "jj",
        &[
            "bookmark",
            "set",
            MAIN_BOOKMARK,
            "-r",
            "@",
            "--allow-backwards",
        ],
        &fx.root,
    );

    let main_before = main_target(&manager).expect("main exists");
    let unrelated_commit = manager
        .resolve_change(&unrelated)
        .expect("resolve unrelated");
    assert_eq!(
        main_before, unrelated_commit.commit_id,
        "precondition: main is at the unrelated advance"
    );

    // Resume must REFUSE the move (non-fast-forward) and park for a human.
    let outcome = resume_from(
        &state,
        &log,
        &manager,
        &issue_id,
        &change,
        PhaseSubstate::RebaseDoneBookmarkPending,
    )
    .expect("a non-fast-forward is a handled outcome, not a hard error");
    assert_eq!(
        outcome,
        LandingOutcome::AwaitingHumanMerge,
        "a non-fast-forward must park for a human, never rewind main"
    );

    // main is UNCHANGED — not moved to the worker's change, not rewound.
    let main_after = main_target(&manager).expect("main still exists");
    assert_eq!(
        main_after, main_before,
        "a rejected non-fast-forward must leave main exactly where it was"
    );
    let landed = manager
        .resolve_change(&change)
        .expect("resolve worker change");
    assert_ne!(
        main_after, landed.commit_id,
        "main must NOT have been moved to the worker's change"
    );

    let issue = state.get_issue(&issue_id).unwrap().unwrap();
    assert_eq!(issue.phase, Phase::AwaitingHumanMerge);
    assert_eq!(issue.phase_substate, None);
}

/// The FF guard is also directly exercised on the primitive: moving a bookmark
/// to a commit that is not a descendant of its current target is refused with
/// [`LandingError::NotFastForward`], and the bookmark does not move.
#[test]
fn fast_forward_bookmark_refuses_non_descendant_target() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");

    // A sibling of main off the baseline — not a descendant of main.
    run(
        "jj",
        &["new", "main-", "-m", "sibling off baseline"],
        &fx.root,
    );
    let sibling = wc_change_id(&fx.root);

    let main_before = main_target(&manager).expect("main exists");
    let sibling_commit = manager.resolve_change(&sibling).expect("resolve sibling");
    assert_ne!(main_before, sibling_commit.commit_id);

    let err = manager
        .fast_forward_bookmark(MAIN_BOOKMARK, &sibling)
        .expect_err("moving to a non-descendant must be refused");
    assert!(
        matches!(err, LandingError::NotFastForward { .. }),
        "expected NotFastForward, got {err:?}"
    );

    assert_eq!(
        main_target(&manager),
        Some(main_before),
        "a refused non-fast-forward must leave the bookmark untouched"
    );
}

/// Re-rebase idempotency (finding #2 / AC-18): resuming from `rebase_started`
/// AFTER the rebase already completed must converge to `phase:merged` without
/// duplicating or re-parenting the change. The change id is stable and `main`
/// ends at exactly that change.
#[test]
fn resume_from_rebase_started_after_rebase_is_idempotent() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);

    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);

    // The rebase already completed pre-crash: the worker's change is a child of
    // main. Persist `rebase_started` — the crash happened right after we wrote
    // that substate but the resume must not blindly re-rebase and diverge.
    manager
        .rebase(&change, MAIN_BOOKMARK)
        .expect("stage: rebase completed pre-crash");
    let commit_after_rebase = manager
        .resolve_change(&change)
        .expect("resolve after staged rebase");
    state
        .set_phase(
            &issue_id,
            Phase::Landing,
            Some(PhaseSubstate::RebaseStarted),
        )
        .expect("persist rebase_started");

    // Resume from `rebase_started`. Because the change is already a descendant
    // of main, the machine must skip the rebase (no rewrite) and drive to merged.
    let outcome = resume_from(
        &state,
        &log,
        &manager,
        &issue_id,
        &change,
        PhaseSubstate::RebaseStarted,
    )
    .expect("resume from rebase_started must complete");
    assert_eq!(outcome, LandingOutcome::Merged);

    // The change was NOT re-parented/duplicated: its commit id is unchanged and
    // main points at exactly it.
    let commit_after_resume = manager
        .resolve_change(&change)
        .expect("resolve after resume");
    assert_eq!(
        commit_after_resume.commit_id, commit_after_rebase.commit_id,
        "resume must not rewrite an already-rebased change"
    );
    assert_eq!(
        main_target(&manager),
        Some(commit_after_resume.commit_id),
        "main must fast-forward to the (unchanged) landed change"
    );
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::Merged
    );
}

/// Resume reads ground truth (finding #2 / REQ-15 / AC-18): resuming from
/// `rebase_done_bookmark_pending` when the bookmark move ALREADY happened
/// (main is already at the target) advances to `phase:merged` WITHOUT a second
/// move — the resume observes `main`'s real position and does not re-run the op.
#[test]
fn resume_from_bookmark_pending_when_move_already_happened() {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);

    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);

    // Reconstruct a crash AFTER the bookmark move but BEFORE the substate was
    // advanced to `bookmark_moved_complete`: rebase ran, main was moved to the
    // change, yet state.db still records `rebase_done_bookmark_pending`.
    manager
        .rebase(&change, MAIN_BOOKMARK)
        .expect("stage: rebase completed pre-crash");
    manager
        .fast_forward_bookmark(MAIN_BOOKMARK, &change)
        .expect("stage: bookmark move completed pre-crash");
    state
        .set_phase(
            &issue_id,
            Phase::Landing,
            Some(PhaseSubstate::RebaseDoneBookmarkPending),
        )
        .expect("persist the crashed-at substate");

    let landed = manager.resolve_change(&change).expect("resolve change");
    assert_eq!(
        main_target(&manager).expect("main exists"),
        landed.commit_id,
        "precondition: the move already happened before resume"
    );

    // Resume must observe main is already at the target and advance to merged
    // without attempting a second move.
    let outcome = resume_from(
        &state,
        &log,
        &manager,
        &issue_id,
        &change,
        PhaseSubstate::RebaseDoneBookmarkPending,
    )
    .expect("resume must complete");
    assert_eq!(outcome, LandingOutcome::Merged);

    assert_eq!(
        main_target(&manager).expect("main exists"),
        landed.commit_id,
        "main is unchanged: the already-done move is not re-run"
    );
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::Merged
    );
}
