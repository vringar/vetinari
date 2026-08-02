//! Deterministic remote-mode landing test (REQ-17 remote path, REQ-2a, AC-12).
//!
//! Drives [`orchestrator::landing::land_remote`] against a *real* jj repository
//! (the `hello` fixture) whose `origin` is a **local bare git repo**, so
//! `jj git push` actually pushes to a reachable remote — while a **fake**
//! [`PrOpener`] stands in for GitHub. This exercises the whole remote-landing
//! state machine + the branch push WITHOUT a live GitHub (the octocrab-backed
//! opener is token-gated and not run here).
//!
//! Asserts:
//! - the issue branch (`vdd/<id>-<slug>`) was pushed to the bare origin (read
//!   back from the bare repo);
//! - the substate machine advanced `push_started → push_done_pr_pending →
//!   pr_created` (observed via the fake opener, which — invoked only after the
//!   push — sees `push_done_pr_pending` persisted and the branch already on
//!   origin, then the terminal transition clears to `phase:pr-open`);
//! - the issue reached `phase:pr-open` with the PR url recorded;
//! - `main` was **not** fast-forwarded (remote mode never moves trunk).
//!
//! Every orchestrator-side `.jj/` op runs through the [`WorkspaceManager`] gate
//! (REQ-5a); the only shell-outs are test-support (bare-repo setup, the worker
//! script, reading jj/git state).

mod common;

use std::cell::RefCell;
use std::path::Path;
use std::process::Command;

use common::{build_fixture, fake_implementer, Fixture};
use orchestrator::events::{EventLog, ORCHESTRATOR_DIR};
use orchestrator::landing::{
    branch_name, land_remote, LandingOutcome, PrOpener, PrRequest, RemoteLanding, MAIN_BOOKMARK,
};
use orchestrator::recovery::{recover_with_opener, RecoveryAction};
use orchestrator::state::{IssueRow, Phase, PhaseSubstate, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_crosslink_api::CrosslinkRepo;

/// Open a fresh `state.db` + `events.jsonl` under the fixture's `.orchestrator/`
/// and seed one issue at `phase:converged` (landing's starting phase).
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

/// The commit `MAIN_BOOKMARK` points at, via the manager gate.
fn main_target(manager: &WorkspaceManager) -> Option<String> {
    manager
        .bookmark_target(MAIN_BOOKMARK)
        .expect("read main bookmark target")
}

/// Whether `git_dir` (a bare repo) has a ref `refs/heads/<branch>` — i.e. the
/// branch was pushed to origin. Read with a test-support `git` (AC-24 scopes the
/// no-shell-out lint to `src/**`).
fn origin_has_branch(git_dir: &Path, branch: &str) -> bool {
    Command::new("git")
        .args([
            "--git-dir",
            git_dir.to_str().unwrap(),
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ])
        .status()
        .expect("git show-ref")
        .success()
}

/// What the fake opener snapshotted at PR-creation time — used to assert PR
/// creation happened *after* the push and at the `push_done_pr_pending` substate.
#[derive(Debug, Clone)]
struct Observed {
    /// The persisted landing substate when `open_pr` was called.
    substate: Option<String>,
    /// Whether the head branch was already on origin at that moment.
    branch_on_origin: bool,
    /// The PR head/base the opener was handed.
    head: String,
    base: String,
}

/// A fake [`PrOpener`] that stands in for GitHub. It records the request it was
/// handed and returns a canned URL — and, crucially, at invocation time it
/// snapshots the persisted landing substate and whether the branch is already on
/// origin, so the test can assert PR creation happened *after* the push and at
/// `push_done_pr_pending`.
///
/// It also models the F2 idempotency contract: `existing_pr` simulates "a PR for
/// this head already exists" (the crash-after-create case). When set,
/// [`PrOpener::find_open_pr`] returns it (so the machine adopts it and never
/// re-creates), and any `open_pr` call flips `open_pr_called` so a test can
/// assert a resume did NOT create a duplicate.
struct FakePrOpener<'a> {
    state: &'a StateDb,
    issue_id: &'a str,
    origin_git_dir: &'a Path,
    url: String,
    observed: RefCell<Option<Observed>>,
    /// When `Some`, an open PR for the head already exists on the remote (F2):
    /// `find_open_pr` returns it and `open_pr` must not be reached.
    existing_pr: Option<String>,
    /// Set true if `open_pr` was ever invoked — a duplicate-create tripwire.
    open_pr_called: RefCell<bool>,
}

impl<'a> FakePrOpener<'a> {
    /// A fresh-landing fake: no pre-existing PR, `open_pr` creates `url`.
    fn new(state: &'a StateDb, issue_id: &'a str, origin_git_dir: &'a Path, url: &str) -> Self {
        FakePrOpener {
            state,
            issue_id,
            origin_git_dir,
            url: url.to_owned(),
            observed: RefCell::new(None),
            existing_pr: None,
            open_pr_called: RefCell::new(false),
        }
    }

    /// A resume fake that simulates GitHub already holding an open PR for the
    /// head (the crash-after-create case): `find_open_pr` returns `existing`.
    fn with_existing_pr(mut self, existing: &str) -> Self {
        self.existing_pr = Some(existing.to_owned());
        self
    }
}

impl PrOpener for FakePrOpener<'_> {
    fn open_pr(&self, req: &PrRequest<'_>) -> Result<String, vetinari_error::LandingError> {
        *self.open_pr_called.borrow_mut() = true;
        let issue = self
            .state
            .get_issue(self.issue_id)
            .expect("read issue in fake opener")
            .expect("issue exists");
        *self.observed.borrow_mut() = Some(Observed {
            substate: issue.phase_substate.clone(),
            branch_on_origin: origin_has_branch(self.origin_git_dir, req.head),
            head: req.head.to_owned(),
            base: req.base.to_owned(),
        });
        Ok(self.url.clone())
    }

    fn find_open_pr(&self, _head: &str) -> Result<Option<String>, vetinari_error::LandingError> {
        Ok(self.existing_pr.clone())
    }
}

/// The required deliverable: with a bare-git `origin` and a fake `PrOpener`,
/// `land_remote` pushes the issue branch, drives the substate machine to
/// `phase:pr-open`, and never touches `main`.
#[test]
fn land_remote_pushes_branch_and_opens_pr_without_touching_main() {
    let fx = build_fixture();

    // A local bare repo as `origin`, added as the jj git remote — so the push is
    // to a real, reachable remote. It lives in its OWN tempdir OUTSIDE the jj
    // working copy, so it is never snapshotted into the worker's change.
    let origin_tmp = tempfile::tempdir().expect("origin tempdir");
    let origin = origin_tmp.path().join("origin.git");
    run(
        "git",
        &["init", "--bare", "--quiet", origin.to_str().unwrap()],
        &fx.root,
    );
    run(
        "jj",
        &["git", "remote", "add", "origin", origin.to_str().unwrap()],
        &fx.root,
    );

    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);

    // The worker commits its change on `@` (a child of `main`), code-only.
    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);

    // Put the fixture into remote landing mode (tracker_remote = origin). Do it
    // on a FRESH change (`jj new` off the reviewed change) so the config edit to
    // `.crosslink/hook-config.json` never pollutes the reviewed change we land.
    // land_remote does not read this directly (the pump's mode gate does), but it
    // exercises CrosslinkRepo::tracker_remote and matches the AC-12 fixture.
    run("jj", &["new"], &fx.root);
    run(
        "crosslink",
        &["config", "set", "tracker_remote", "origin"],
        &fx.root,
    );

    let main_before = main_target(&manager).expect("fixture creates a main bookmark");
    let branch = branch_name(
        &issue_id,
        "Add a hello-world say_hi function with a passing test",
    );
    assert!(
        branch.starts_with(&format!("vdd/{issue_id}-")),
        "branch `{branch}` must be vdd/<id>-<slug> (design Q2)"
    );

    let opener = FakePrOpener::new(
        &state,
        &issue_id,
        &origin,
        "https://github.com/acme/hello/pull/7",
    );

    let outcome = land_remote(
        &state,
        &log,
        &manager,
        &opener,
        &RemoteLanding {
            issue_id: &issue_id,
            change_revset: &change,
            remote: "origin",
            branch: &branch,
            base: MAIN_BOOKMARK,
            title: "Add say_hi",
            body: "Adds `say_hi` returning \"hello\", with a unit test.",
        },
    )
    .expect("remote landing must succeed");

    // Outcome carries the PR url.
    assert_eq!(
        outcome,
        LandingOutcome::PrOpen {
            url: "https://github.com/acme/hello/pull/7".to_owned()
        },
        "remote landing returns PrOpen with the opener's url"
    );

    // The branch was pushed to the bare origin.
    assert!(
        origin_has_branch(&origin, &branch),
        "the issue branch `{branch}` must exist on the bare origin after the push"
    );

    // Substate ordering: the PR was opened only AFTER the push completed and the
    // machine had persisted `push_done_pr_pending` — proving
    // push_started → push_done_pr_pending precede pr creation.
    let observed = opener
        .observed
        .borrow()
        .clone()
        .expect("the fake opener must have been invoked exactly once");
    assert_eq!(
        observed.substate.as_deref(),
        Some("push_done_pr_pending"),
        "at PR-creation time the persisted substate must be push_done_pr_pending"
    );
    assert!(
        observed.branch_on_origin,
        "the branch must already be on origin before the PR is opened (push precedes PR)"
    );
    assert_eq!(
        observed.head, branch,
        "the PR head is the pushed issue branch"
    );
    assert_eq!(observed.base, MAIN_BOOKMARK, "the PR base is main");

    // The issue reached phase:pr-open with the substate cleared.
    let issue = state.get_issue(&issue_id).unwrap().unwrap();
    assert_eq!(issue.phase, Phase::PrOpen, "terminal phase is pr-open");
    assert_eq!(issue.phase_substate, None, "pr-open clears the substate");

    // main was NOT fast-forwarded — remote mode never moves trunk.
    let main_after = main_target(&manager).expect("main still exists");
    assert_eq!(
        main_after, main_before,
        "remote mode must leave the main bookmark exactly where it was"
    );
    let landed = manager
        .resolve_change(&change)
        .expect("resolve landed change");
    assert_ne!(
        main_after, landed.commit_id,
        "main must NOT have advanced to the pushed change"
    );

    // The pr-open transition event recorded the url + branch (durable trail).
    let events = state.recent_events(20).expect("read events");
    let pr_event = events
        .iter()
        .find(|e| e.payload.get("to_phase").and_then(|v| v.as_str()) == Some("pr-open"))
        .expect("a landing → pr-open transition event was emitted");
    assert_eq!(
        pr_event.payload.get("pr_url").and_then(|v| v.as_str()),
        Some("https://github.com/acme/hello/pull/7")
    );
    assert_eq!(
        pr_event.payload.get("branch").and_then(|v| v.as_str()),
        Some(branch.as_str())
    );

    // And the crosslink mode gate reads back as remote (origin).
    let crosslink = vetinari_crosslink_api::CrosslinkRepo::open(&fx.root).expect("open crosslink");
    assert_eq!(
        crosslink
            .tracker_remote()
            .expect("read tracker_remote")
            .as_deref(),
        Some("origin"),
        "the fixture is in remote landing mode"
    );
}

// ============================================================================
// Crash / resume coverage (F1 + F2): recovery resumes a mid-flight remote
// landing deterministically instead of quarantining and orphaning the branch.
//
// These drive the REAL recovery table (`recover_with_opener`) with a fake
// PrOpener + local bare-git origin. They PROVE F1+F2: against the pre-fix code a
// push_*/pr_* substate hit the recovery catch-all → StateDbInconsistent → the
// issue quarantined at phase:orchestrator-error, so every assertion of
// `phase:pr-open` below would fail.
// ============================================================================

/// Stand up a fixture in remote landing mode: a bare-git `origin`, the worker's
/// reviewed change committed, and `tracker_remote = origin`. Returns the origin
/// tempdir (keep alive for the test), the bare repo path, the reviewed change
/// id, and the per-issue branch name recovery reconstructs from the issue title.
fn prepare_remote_landing(fx: &Fixture) -> (tempfile::TempDir, std::path::PathBuf, String, String) {
    let origin_tmp = tempfile::tempdir().expect("origin tempdir");
    let origin = origin_tmp.path().join("origin.git");
    run(
        "git",
        &["init", "--bare", "--quiet", origin.to_str().unwrap()],
        &fx.root,
    );
    run(
        "jj",
        &["git", "remote", "add", "origin", origin.to_str().unwrap()],
        &fx.root,
    );
    // The worker commits its reviewed change on `@` (a child of `main`).
    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);
    // Put the fixture into remote mode on a FRESH change so the config edit never
    // pollutes the reviewed change.
    run("jj", &["new"], &fx.root);
    run(
        "crosslink",
        &["config", "set", "tracker_remote", "origin"],
        &fx.root,
    );
    // The branch recovery derives is `vdd/<id>-<slug>` off the crosslink title —
    // reconstruct it here identically so the test pushes the exact same branch.
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");
    let title = crosslink.read_issue(fx.issue_id).expect("read issue").title;
    let branch = branch_name(&fx.issue_id.to_string(), &title);
    (origin_tmp, origin, change, branch)
}

/// (a) A crash at `push_done_pr_pending` — the branch is already pushed and
/// GitHub already holds the PR (create landed before the substate advanced).
/// Recovery must RESUME to `phase:pr-open` adopting the existing PR, WITHOUT
/// re-creating it (no 422) and WITHOUT re-pushing.
#[test]
fn recovery_resumes_push_done_pr_pending_adopting_existing_pr() {
    let fx = build_fixture();
    let (_origin_tmp, origin, change, branch) = prepare_remote_landing(&fx);
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");

    // Simulate the push having already happened (exactly what push_step does
    // before the crash): point the branch at the reviewed change and push it.
    manager
        .point_bookmark(&branch, &change)
        .expect("point issue branch");
    manager
        .git_push("origin", &branch)
        .expect("push issue branch");
    assert!(
        origin_has_branch(&origin, &branch),
        "precondition: branch pushed to origin"
    );

    // Persist the crash point.
    state
        .set_phase(
            &issue_id,
            Phase::Landing,
            Some(PhaseSubstate::PushDonePrPending),
        )
        .expect("persist push_done_pr_pending");

    // GitHub already holds an open PR for the head (crash after create): the fake
    // adopts it via find_open_pr and must NEVER reach open_pr.
    let existing = "https://github.com/acme/hello/pull/42";
    let opener = FakePrOpener::new(&state, &issue_id, &origin, "https://MUST-NOT-CREATE")
        .with_existing_pr(existing);

    let actions = recover_with_opener(&state, &log, &manager, Some(&crosslink), &opener)
        .expect("recovery must succeed");

    assert_eq!(
        actions,
        vec![RecoveryAction::ResumedLanding {
            issue_id: issue_id.clone(),
            outcome: LandingOutcome::PrOpen {
                url: existing.to_owned()
            },
        }],
        "must resume to pr-open adopting the existing PR, got {actions:?}"
    );
    assert!(
        !*opener.open_pr_called.borrow(),
        "a push_done_pr_pending resume must NOT re-create the PR (F2 idempotency)"
    );
    let issue = state.get_issue(&issue_id).unwrap().unwrap();
    assert_eq!(issue.phase, Phase::PrOpen, "resumed to pr-open");
    assert_eq!(issue.phase_substate, None, "pr-open clears the substate");
    assert!(
        origin_has_branch(&origin, &branch),
        "branch stays on origin (no re-push, remote branch is the PR head)"
    );
}

/// (b) A crash at `push_started`. Recovery must RESUME: re-point + re-push the
/// branch (idempotent) and open the PR (none existed yet, so creating it is
/// correct, not a duplicate) → `phase:pr-open`.
#[test]
fn recovery_resumes_push_started() {
    let fx = build_fixture();
    let (_origin_tmp, origin, change, branch) = prepare_remote_landing(&fx);
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");

    // Crash just after set_phase(push_started): the branch bookmark exists (the
    // pointed change) but was NOT yet pushed, so the resume must perform the
    // push. (Recovery uses the branch bookmark as the change revset.)
    manager
        .point_bookmark(&branch, &change)
        .expect("point issue branch");
    assert!(
        !origin_has_branch(&origin, &branch),
        "precondition: branch NOT yet on origin"
    );
    state
        .set_phase(&issue_id, Phase::Landing, Some(PhaseSubstate::PushStarted))
        .expect("persist push_started");

    // No pre-existing PR: the resume creates it (find_open_pr → None → open_pr).
    let created = "https://github.com/acme/hello/pull/7";
    let opener = FakePrOpener::new(&state, &issue_id, &origin, created);

    let actions = recover_with_opener(&state, &log, &manager, Some(&crosslink), &opener)
        .expect("recovery must succeed");

    assert_eq!(
        actions,
        vec![RecoveryAction::ResumedLanding {
            issue_id: issue_id.clone(),
            outcome: LandingOutcome::PrOpen {
                url: created.to_owned()
            },
        }],
        "push_started must resume through push → PR → pr-open, got {actions:?}"
    );
    assert!(
        *opener.open_pr_called.borrow(),
        "no PR existed, so the resume must create one"
    );
    assert!(
        origin_has_branch(&origin, &branch),
        "the resume performed the push (branch now on origin)"
    );
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::PrOpen
    );
}

/// (c) A crash at `pr_created` — GitHub has the PR, only the terminal transition
/// to `phase:pr-open` did not commit. Recovery re-derives the PR url and
/// finishes, without a re-create or re-push.
#[test]
fn recovery_resumes_pr_created() {
    let fx = build_fixture();
    let (_origin_tmp, origin, change, branch) = prepare_remote_landing(&fx);
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    let (state, log, issue_id) = seed(&fx);
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink");

    manager
        .point_bookmark(&branch, &change)
        .expect("point issue branch");
    manager
        .git_push("origin", &branch)
        .expect("push issue branch");
    state
        .set_phase(&issue_id, Phase::Landing, Some(PhaseSubstate::PrCreated))
        .expect("persist pr_created");

    let existing = "https://github.com/acme/hello/pull/99";
    let opener = FakePrOpener::new(&state, &issue_id, &origin, "https://MUST-NOT-CREATE")
        .with_existing_pr(existing);

    let actions = recover_with_opener(&state, &log, &manager, Some(&crosslink), &opener)
        .expect("recovery must succeed");

    assert_eq!(
        actions,
        vec![RecoveryAction::ResumedLanding {
            issue_id: issue_id.clone(),
            outcome: LandingOutcome::PrOpen {
                url: existing.to_owned()
            },
        }],
        "pr_created must finish the terminal transition, got {actions:?}"
    );
    assert!(
        !*opener.open_pr_called.borrow(),
        "a pr_created resume must NOT re-create the PR"
    );
    assert_eq!(
        state.get_issue(&issue_id).unwrap().unwrap().phase,
        Phase::PrOpen
    );
}
