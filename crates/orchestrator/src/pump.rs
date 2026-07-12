//! The build pump — the integration keystone that drives one crosslink issue
//! from `phase:graphed` to `phase:merged`, headless (REQ-16, REQ-13, AC-11a).
//!
//! The pump ties every other module together. Each [`tick`](BuildPump::tick)
//! runs two steps whose separation is the load-bearing REQ-2 property:
//!
//! 1. **Ingest** — the *only* place a crosslink label is ever read as a work
//!    signal. It polls `list_by_label("open", "phase:graphed")` (open, graphed,
//!    no open blockers — Q1's strict pickup) and, for each such issue **not yet
//!    in `state.db`**, inserts a fresh `IssueRow(phase=Graphed)`. This discovers
//!    new work exactly once; thereafter the label is irrelevant to routing.
//! 2. **Drive** — authority is `state.db`. It selects issues whose persisted
//!    [`Phase`] is *drivable* (non-terminal, non-parked: `Graphed`, or a
//!    requeued `Implementing`/`QaGate`), under the concurrency budget (REQ-13),
//!    and drives each through its per-issue state machine. The decision of
//!    *what* to drive reads `state.db`, never a label — so a QA-failed issue
//!    (moved to `Implementing` in `state.db`, with its graphed label already
//!    gone) is still re-driven, and after a restart an in-flight issue is picked
//!    up from `state.db`.
//!
//! Labels are still *mirrored* for presentation (REQ-2) so `crosslink issue
//! show` matches the pump's authority — but a mirrored label is never read back
//! to make a routing decision.
//!
//! # The per-issue state machine (MVP: QA pass → land directly)
//!
//! ```text
//!   graphed
//!     └─ label phase:implementing, prepare workspace on `main`,
//!        spawn the Direct fake worker, wait
//!          └─ verify DONE (S3)  ── missing ─▶ orchestrator-error (crash)
//!             └─ translate artifacts → crosslink comments (idempotent, REQ-3b)
//!                └─ qa-gate (S5): QaGate::run()
//!                     ├─ Pass ─▶ landing (L2: land_local)
//!                     │            ├─ Merged            ─▶ phase:merged (cleanup)
//!                     │            └─ AwaitingHumanMerge ─▶ (terminal, parked)
//!                     ├─ Fail ─▶ blocker comment + back to implementing
//!                     │           (bounded retries; MVP fixture passes first try)
//!                     └─ Err(poison) ─▶ orchestrator-error
//! ```
//!
//! For the MVP the convergence rule is *QA pass → land* — there is **no**
//! Adversary loop (that is iteration 2). The `Fail` path is **live**: a failing
//! QA gate posts a blocker, bumps the round, and re-queues the issue at
//! `Implementing` **in `state.db`**; the next tick's drive step re-selects it
//! from `state.db` (the label is already off `phase:graphed`) and re-spawns a
//! fresh worker. That loop is bounded by [`MAX_QA_RETRIES`]; the AC-11a fixture
//! passes on the first try. (Before the ingest/drive split this retry was dead
//! code — a requeued issue was never re-selected — which is exactly the bug this
//! structure fixes.)
//!
//! # State authority (REQ-2): decisions read `state.db`, never labels
//!
//! The pump's next action derives from the typed [`Phase`] in `state.db` plus
//! workspace artifacts (the DONE sentinel, the QA verdict) — **never** from
//! crosslink's `phase:*` labels. The one place a label is read is the ingest
//! step, and even there the label only *discovers* an issue to insert into
//! `state.db`; once inserted, routing is 100% `state.db`. Labels are written as
//! a *presentation* mirror of the authoritative phase (REQ-2), so a human
//! reading `crosslink issue show` sees the same phase the pump acts on, but the
//! pump never reads them back to decide.
//!
//! # Single writer to crosslink (REQ-3)
//!
//! Workers never mutate crosslink. The pump is the sole writer: it posts the
//! translated artifact comments with the orchestrator's `role=implementer`
//! attribution and moves the `phase:*` labels. Comment translation is idempotent
//! against the `posted_artifacts` ledger (REQ-3b), so a crash mid-translation
//! re-posts nothing.
//!
//! # No shell-out (AC-24)
//!
//! The pump constructs no `std::process::Command`. Its worker runs as a
//! `WorkerCommand::Direct` through the `Spawner` (zellij-hosted); its QA runs
//! `bash static_qa.sh` through [`QaGate`] (the sanctioned exception); its jj
//! work goes through the [`WorkspaceManager`] gate; and crosslink is reached only
//! through [`CrosslinkRepo`]. There is no `unwrap`/`panic` on any non-test path.

#![allow(clippy::result_large_err)]

use std::path::PathBuf;
use std::time::Duration;

use miette::Diagnostic;
use serde_json::json;
use thiserror::Error;
use uuid::Uuid;
use vetinari_crosslink_api::CrosslinkRepo;

use crate::artifacts::{ArtifactSet, DoneSentinel};
use crate::config::OrchestratorConfig;
use crate::events::{emit, EventLog};
use crate::landing::{land_local, LandingOutcome};
use crate::qa::{QaGate, QaOutcome};
use crate::spawn::{SpawnOutcome, Spawner, WorkerCommand};
use crate::state::{ActiveWorkerRow, EventKind, IssueRow, Phase, StateDb, WorkerRole};
use crate::workspace::{WorkspaceManager, WorkspaceName};

/// The crosslink label prefix the pump moves as it advances an issue (REQ-2:
/// presentation only). `phase:<phase-token>`, where the token is the same one
/// `state.db` stores (e.g. `phase:graphed`, `phase:merged`).
pub const PHASE_LABEL_PREFIX: &str = "phase:";

/// The label the build pump picks up on: open issues carrying it are the pump's
/// work queue (Q1 strict policy — unphased issues are ignored).
pub const GRAPHED_LABEL: &str = "phase:graphed";

/// The role attribution recorded on translated crosslink comments (AC-16). The
/// worker is the fake/real Implementer; the pump posts on its behalf.
pub const WORKER_ROLE_TAG: &str = "implementer";

/// The base revset a fresh worker workspace is rooted on: `main`, so the
/// worker's change is a child of trunk and lands as a clean fast-forward
/// (REQ-17 local path).
pub const WORKER_BASE_REVSET: &str = "main";

/// How many times QA may fail-and-re-spawn before the pump gives up and parks
/// the issue at `orchestrator-error`. The MVP fixture passes first try; this
/// bounds a genuinely-failing worker so the pump can't loop forever.
pub const MAX_QA_RETRIES: i64 = 3;

/// Failure of a pump operation that is not itself an issue-level outcome.
///
/// Issue-level failures (a missing DONE, a QA failure, a landing conflict) are
/// *not* `PumpError`s — they are handled in-band by transitioning the issue to
/// the right phase and emitting an event. A `PumpError` is a pump-wide fault:
/// crosslink is unreachable, `state.db` is broken, or the worker host is
/// unavailable. These abort the tick.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum PumpError {
    /// A crosslink adapter operation failed.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Crosslink(#[from] vetinari_crosslink_api::CrosslinkError),

    /// A `state.db` operation failed.
    #[error(transparent)]
    #[diagnostic(transparent)]
    State(#[from] vetinari_error::StateError),

    /// A worker spawn / host operation failed.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Spawn(#[from] vetinari_error::SpawnError),

    /// A landing (rebase / bookmark-move) operation failed.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Landing(#[from] vetinari_error::LandingError),

    /// A worker artifact could not be verified or translated.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Artifact(#[from] vetinari_error::ArtifactError),

    /// The pump could not locate the worker's committed change to land — the
    /// prepared workspace has no working-copy commit registered (should be
    /// impossible after a clean `prepare` + worker run).
    #[error(
        "no working-copy commit found for workspace `{workspace}` — cannot land issue #{issue_id}"
    )]
    #[diagnostic(code(vetinari::pump::landing_target_missing))]
    LandingTargetMissing {
        /// The workspace whose working copy could not be resolved.
        workspace: String,
        /// The issue the pump was landing.
        issue_id: i64,
    },

    /// The configured worker command is empty — the pump has nothing to spawn.
    #[error("orchestrator config has an empty worker argv — nothing to spawn")]
    #[diagnostic(
        code(vetinari::pump::empty_worker_command),
        help("Set `[worker] argv = [...]` in .orchestrator/config.toml, or remove it to use the default.")
    )]
    EmptyWorkerCommand,
}

/// The outcome of driving one issue's state machine in a single tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueOutcome {
    /// The issue reached `phase:merged` — landed locally.
    Merged,
    /// The issue is parked at `phase:awaiting-human-merge` (a landing conflict;
    /// the Merger role is deferred).
    AwaitingHumanMerge,
    /// The issue was re-queued at `phase:implementing` after a QA failure
    /// (blocker posted; a later tick re-drives it).
    Requeued,
    /// The issue hit a poison fault (missing DONE, QA poison, retry budget
    /// exhausted) and is parked at `phase:orchestrator-error`.
    OrchestratorError,
}

impl IssueOutcome {
    /// Whether this outcome is terminal — the pump will not pick the issue up
    /// again. `Requeued` is the only non-terminal outcome.
    pub fn is_terminal(self) -> bool {
        !matches!(self, IssueOutcome::Requeued)
    }
}

/// The build pump (REQ-16). Owns the handles every phase transition needs and
/// drives issues through the per-issue state machine.
///
/// Not `Clone`: the pump is the single-threaded tick loop's sole owner of the
/// `state.db` connection and the crosslink single-writer identity (REQ-2,
/// REQ-3). The [`WorkspaceManager`] it holds *is* the shared `.jj/` gate
/// (REQ-5a), so its landing ops serialize against any future concurrent lander.
pub struct BuildPump {
    config: OrchestratorConfig,
    state: StateDb,
    log: EventLog,
    manager: WorkspaceManager,
    spawner: Spawner,
    crosslink: CrosslinkRepo,
}

impl BuildPump {
    /// Assemble a pump from its collaborators.
    ///
    /// - `config` — the parsed `.orchestrator/config.toml` (REQ-13).
    /// - `state` — the authoritative `state.db` (REQ-2). The pump is its sole
    ///   writer during the loop.
    /// - `log` — the `events.jsonl` mirror (REQ-14); every transition emits.
    /// - `manager` — the `.jj/` gate for workspace prep and landing (REQ-5a).
    /// - `spawner` — hosts the Direct worker in a zellij pane (REQ-1d).
    /// - `crosslink` — the single-writer crosslink handle (REQ-3): the poll
    ///   source and the comment/label sink.
    pub fn new(
        config: OrchestratorConfig,
        state: StateDb,
        log: EventLog,
        manager: WorkspaceManager,
        spawner: Spawner,
        crosslink: CrosslinkRepo,
    ) -> Self {
        BuildPump {
            config,
            state,
            log,
            manager,
            spawner,
            crosslink,
        }
    }

    /// The poll interval between ticks (REQ-13).
    pub fn poll_interval(&self) -> Duration {
        self.config.poll_interval()
    }

    /// One pump tick: **ingest** new graphed work into `state.db` (the only
    /// label read), then **drive** every drivable `state.db` issue — up to the
    /// concurrency budget (REQ-13) — through its state machine. Returns the
    /// per-issue outcomes in pickup (ascending id) order.
    ///
    /// The two steps enforce REQ-2: ingest reads a crosslink label solely to
    /// *discover* an issue and seed its `state.db` row; the drive step then
    /// decides what to run purely from the persisted [`Phase`], never a label.
    /// Because each issue is driven synchronously to a terminal-or-requeued
    /// phase before the next is picked, the budget caps how many issues one tick
    /// *starts*, giving the strict serialization AC-10 asserts at
    /// `max_concurrent_agents = 1`.
    pub fn tick(&self) -> Result<Vec<(i64, IssueOutcome)>, PumpError> {
        // Step 1 — ingest: the ONLY label read. Discover open, graphed,
        // unblocked issues and seed a state.db row for any not yet tracked.
        self.ingest()?;

        // Step 2 — drive: authority is state.db. Select drivable issues from
        // state.db (never a label) and drive each under the budget.
        let budget = self.config.max_concurrent_agents as usize;
        let mut outcomes = Vec::new();
        for issue_id in self.drivable_issue_ids()?.into_iter().take(budget) {
            let outcome = self.drive_issue(issue_id)?;
            outcomes.push((issue_id, outcome));
        }
        Ok(outcomes)
    }

    /// Drive [`tick`](Self::tick) repeatedly until no drivable work remains in
    /// `state.db` — the headless dogfood loop (AC-11a).
    ///
    /// Idle is defined against `state.db` authority (REQ-2): the loop stops once
    /// a tick both produced no non-terminal (`Requeued`) outcome **and** left no
    /// issue in a drivable phase. A `Requeued` outcome (QA failed → back to
    /// `Implementing` in `state.db`) is not idle — the next tick re-selects that
    /// issue from `state.db` and re-spawns a fresh worker — so the loop keeps
    /// going until every issue lands, parks, or exhausts its retry budget.
    ///
    /// When work remains the loop sleeps `poll_interval` (REQ-13) between ticks
    /// rather than busy-spinning (#5). Returns every `(issue_id, outcome)`
    /// observed across all ticks.
    pub fn run_until_idle(&self) -> Result<Vec<(i64, IssueOutcome)>, PumpError> {
        let mut all = Vec::new();
        loop {
            let outcomes = self.tick()?;
            let any_requeued = outcomes
                .iter()
                .any(|(_, o)| matches!(o, IssueOutcome::Requeued));
            all.extend(outcomes);
            // Idle only when nothing was requeued AND state.db holds no more
            // drivable work (e.g. a budget-capped tick that started fewer issues
            // than were drivable). Otherwise sleep the poll interval and tick
            // again rather than busy-spinning.
            let more_drivable = !self.drivable_issue_ids()?.is_empty();
            if !any_requeued && !more_drivable {
                break;
            }
            std::thread::sleep(self.poll_interval());
        }
        Ok(all)
    }

    // --- ingest (the ONLY label read, REQ-2) --------------------------------

    /// Ingest step: discover new graphed work from crosslink and seed it into
    /// `state.db`. This is the sole place a `phase:*` label drives a decision.
    ///
    /// Q1-strict pickup: an issue is ingested only if it is **open**, carries
    /// `phase:graphed`, and has **no open blockers** (REQ-16). For each such
    /// issue not already tracked in `state.db`, a fresh `IssueRow(Graphed)` is
    /// inserted. An issue already in `state.db` is left untouched — its
    /// authoritative phase (which may have advanced past `Graphed`, or been
    /// requeued to `Implementing`) is never overwritten from a stale label.
    fn ingest(&self) -> Result<(), PumpError> {
        let graphed = self.crosslink.list_by_label("open", GRAPHED_LABEL)?;
        for issue in graphed {
            if !self.crosslink.open_blockers(issue.id)?.is_empty() {
                continue;
            }
            let key = issue.id.to_string();
            if self.state.get_issue(&key)?.is_none() {
                self.state
                    .upsert_issue(&IssueRow::new(&key, Phase::Graphed))?;
            }
        }
        Ok(())
    }

    // --- drive selection (authority = state.db, REQ-2) ----------------------

    /// The ids of every issue whose persisted `state.db` phase is drivable
    /// ([`Phase::is_drivable`]), in ascending id order. This is the drive step's
    /// work queue — read purely from `state.db`, never from a crosslink label,
    /// so a requeued or crash-interrupted issue is re-selected without any label
    /// still saying `phase:graphed`.
    fn drivable_issue_ids(&self) -> Result<Vec<i64>, PumpError> {
        let mut ids: Vec<i64> = self
            .state
            .list_issues()?
            .into_iter()
            .filter(|row| row.phase.is_drivable())
            .filter_map(|row| row.issue_id.parse::<i64>().ok())
            .collect();
        ids.sort_unstable();
        Ok(ids)
    }

    // --- per-issue state machine --------------------------------------------

    /// Drive one drivable `state.db` issue to a terminal-or-requeued phase.
    ///
    /// The caller ([`tick`](Self::tick)) selected this issue from `state.db`
    /// (never a label). This runs the implement → verify → translate → QA → land
    /// pipeline for the current round. Every phase transition writes `state.db`
    /// (the authority), mirrors the `phase:*` label to crosslink (presentation),
    /// and emits an event (REQ-14).
    ///
    /// While a worker is in flight an `active_workers` row is persisted (#2) so
    /// the `posted_artifacts` ledger (REQ-3b) has a stable identity and P2's
    /// crash-recovery (#16) has the state it needs; the row is removed on every
    /// completion/cleanup path. **P1 does not itself recover a crashed worker
    /// from that row** — it only persists it; cross-restart recovery is deferred
    /// to #16 P2.
    fn drive_issue(&self, issue_id: i64) -> Result<IssueOutcome, PumpError> {
        let key = issue_id.to_string();

        // graphed/implementing → implementing: prepare a fresh workspace, spawn
        // the worker, wait. The `from` phase is read from state.db (authority)
        // so a requeued issue's event reads `implementing→implementing`, not a
        // fabricated `graphed→…`.
        let round = self.current_round(&key)?;
        let from = self
            .state
            .get_issue(&key)?
            .map(|i| i.phase)
            .unwrap_or(Phase::Graphed);
        self.transition(&key, from, Phase::Implementing, "build pump pickup")?;

        let name = WorkspaceName::generate(Phase::Implementing, &key, round);
        let prepared = self.manager.prepare(&name, WORKER_BASE_REVSET)?;
        // Mint the worker identity ONCE for this attempt and persist it as an
        // active_workers row (#2). Keeping the uuid stable for the attempt makes
        // the posted_artifacts ledger (REQ-3b) dedupe a re-translation within the
        // run; persisting the row gives P2 (#16) the state to recover from.
        let worker_uuid = Uuid::new_v4().simple().to_string();
        self.register_worker(&key, &worker_uuid, round, prepared.path())?;

        let command = self.worker_command()?;
        let handle =
            self.spawner
                .spawn(WorkerRole::Implementer, &key, round, &prepared, &command)?;
        emit(
            &self.state,
            &self.log,
            EventKind::Spawn,
            Some(&key),
            Some(&worker_uuid),
            &json!({
                "role": WORKER_ROLE_TAG,
                "round": round,
                "pane": handle.pane.name.clone(),
                "workspace": name.as_str(),
            }),
        )?;

        let outcome = handle.wait(self.config.worker_timeout(), Duration::from_millis(300))?;
        if outcome == SpawnOutcome::StillRunning {
            // The worker outran its budget without producing a DONE — a stall,
            // treated like a crash (REQ-13). Before cleaning the workspace, make
            // sure the worker is actually gone (#3): close the pane AND verify it
            // is dead, so the forget+rm below does not race a surviving child.
            let _confirmed_dead =
                handle.close_and_wait(Duration::from_secs(5), Duration::from_millis(200));
            self.remove_worker(&worker_uuid);
            return self.poison(
                &key,
                &name,
                &format!("worker for #{issue_id} exceeded its timeout without exiting"),
            );
        }
        // Clean exit: the pane closed itself on command exit (--close-on-exit).
        // Still best-effort close to be safe; a self-closed pane is idempotent.
        handle.close();

        // Verify the DONE sentinel (S3). Absence — regardless of exit code — is a
        // crash (REQ-3b): poison + workspace cleanup.
        let done = match DoneSentinel::verify(prepared.path()) {
            Ok(done) => done,
            Err(source) => {
                emit(
                    &self.state,
                    &self.log,
                    EventKind::Transition,
                    Some(&key),
                    Some(&worker_uuid),
                    &json!({"error": "done_sentinel_missing", "detail": source.to_string()}),
                )?;
                self.remove_worker(&worker_uuid);
                return self.poison(
                    &key,
                    &name,
                    &format!("worker for #{issue_id} left no valid DONE sentinel: {source}"),
                );
            }
        };

        // Translate artifacts → crosslink comments (REQ-3, idempotent REQ-3b).
        self.translate_artifacts(issue_id, &worker_uuid, &done)?;

        // Empty-commit guard (#4): a worker that wrote a valid DONE but made no
        // change (never edited the tree / never `jj describe`d) leaves a working
        // copy identical to `main`. Fast-forwarding that would advance `main` to
        // a no-op commit and falsely report Merged. Refuse to land it — treat it
        // as a worker failure and poison the issue instead.
        if !self
            .manager
            .change_differs_from(WORKER_BASE_REVSET, &self.change_revset(&name, issue_id)?)?
        {
            self.remove_worker(&worker_uuid);
            return self.poison(
                &key,
                &name,
                &format!(
                    "worker for #{issue_id} produced an empty change (no diff vs `{WORKER_BASE_REVSET}`) — refusing to land"
                ),
            );
        }

        // qa-gate (S5).
        self.transition(
            &key,
            Phase::Implementing,
            Phase::QaGate,
            "worker committed; running QA",
        )?;
        let qa = QaGate::new(prepared.path()).with_timeout(self.config.qa_timeout());
        match qa.run() {
            Ok(QaOutcome::Pass) => {
                emit(
                    &self.state,
                    &self.log,
                    EventKind::QaResult,
                    Some(&key),
                    Some(&worker_uuid),
                    &json!({"result": "pass"}),
                )?;
                self.remove_worker(&worker_uuid);
                self.land(issue_id, &key, &name, &prepared)
            }
            Ok(QaOutcome::Fail {
                exit_code,
                output_tail,
            }) => {
                emit(
                    &self.state,
                    &self.log,
                    EventKind::QaResult,
                    Some(&key),
                    Some(&worker_uuid),
                    &json!({"result": "fail", "exit_code": exit_code}),
                )?;
                self.remove_worker(&worker_uuid);
                self.on_qa_fail(issue_id, &key, &name, exit_code, output_tail.as_str())
            }
            Err(source) => {
                // Poison: a broken/killed/timed-out gate is orchestrator-error,
                // never a blocker (the qa module's load-bearing distinction).
                emit(
                    &self.state,
                    &self.log,
                    EventKind::QaResult,
                    Some(&key),
                    Some(&worker_uuid),
                    &json!({"result": "poison", "detail": source.to_string()}),
                )?;
                self.remove_worker(&worker_uuid);
                self.poison(
                    &key,
                    &name,
                    &format!("QA gate for #{issue_id} is broken/poison: {source}"),
                )
            }
        }
    }

    /// QA passed → land the worker's committed change (L2) and, on a clean land,
    /// clean up the workspace and mirror `phase:merged`.
    fn land(
        &self,
        issue_id: i64,
        key: &str,
        name: &WorkspaceName,
        prepared: &crate::workspace::PreparedWorkspace,
    ) -> Result<IssueOutcome, PumpError> {
        // The change to land is the worker's committed working-copy commit —
        // read AFTER the worker ran `jj describe`, so it is the describe'd
        // commit, not the empty pre-run one.
        let _ = prepared;
        let change = self.change_revset(name, issue_id)?;
        // land_local drives the whole rebase → fast-forward substate machine and
        // owns the Landing/Merged/AwaitingHumanMerge transitions + events.
        let outcome = land_local(&self.state, &self.log, &self.manager, key, &change)?;
        match outcome {
            LandingOutcome::Merged => {
                // Cleanup the ephemeral workspace and mirror the terminal label.
                self.manager.forget(name)?;
                self.set_phase_label(issue_id, Phase::Merged)?;
                Ok(IssueOutcome::Merged)
            }
            LandingOutcome::AwaitingHumanMerge => {
                // Parked for a human; leave the workspace for inspection but
                // mirror the label so the crosslink trail shows the block.
                self.set_phase_label(issue_id, Phase::AwaitingHumanMerge)?;
                Ok(IssueOutcome::AwaitingHumanMerge)
            }
        }
    }

    /// QA failed → post a `--kind blocker` and either re-queue at
    /// `implementing` (round++) or, if the retry budget is spent, poison.
    fn on_qa_fail(
        &self,
        issue_id: i64,
        key: &str,
        name: &WorkspaceName,
        exit_code: i32,
        output_tail: &str,
    ) -> Result<IssueOutcome, PumpError> {
        // Post the failing output as a blocker for the (re-spawned) worker
        // (REQ-9, AC-7). The pump is the single writer (REQ-3).
        let body =
            format!("Static QA failed (exit {exit_code}). Last output:\n\n```\n{output_tail}\n```");
        self.crosslink
            .comment_write(issue_id, "blocker", &body, Some(WORKER_ROLE_TAG))?;

        // Clean up the failed attempt's workspace (REQ-12: a fresh spawn re-preps
        // anyway, but forget now so an orphan doesn't linger).
        self.manager.forget(name)?;

        let issue = self.state.get_issue(key)?;
        let round = issue.as_ref().map(|i| i.round).unwrap_or(0);
        if round + 1 >= MAX_QA_RETRIES {
            return self.poison(
                key,
                name,
                &format!("QA for #{issue_id} still failing after {MAX_QA_RETRIES} attempts"),
            );
        }
        // Bump the round and re-queue at implementing; a later tick re-drives.
        if let Some(mut issue) = issue {
            issue.round = round + 1;
            issue.phase = Phase::Implementing;
            issue.phase_substate = None;
            self.state.upsert_issue(&issue)?;
        }
        self.transition(
            key,
            Phase::QaGate,
            Phase::Implementing,
            "QA failed — blocker posted, re-spawning",
        )?;
        Ok(IssueOutcome::Requeued)
    }

    // --- helpers ------------------------------------------------------------

    /// Build the Direct worker command from config, resolving the argv against
    /// the repository root (so a relative fixture path works from any cwd).
    fn worker_command(&self) -> Result<WorkerCommand, PumpError> {
        let argv = self
            .config
            .worker_argv(self.manager.root())
            .ok_or(PumpError::EmptyWorkerCommand)?;
        Ok(WorkerCommand::direct(argv, Vec::<(String, String)>::new()))
    }

    /// The worker's committed change: the working-copy commit id of the prepared
    /// workspace, read from the repo's workspace list *after* the worker ran (so
    /// it is the `jj describe`'d commit). Used both as the empty-commit guard's
    /// diff target (#4) and as the landing target.
    fn change_revset(&self, name: &WorkspaceName, issue_id: i64) -> Result<String, PumpError> {
        let name_str = name.as_str();
        let entries = self.manager.entries()?;
        entries
            .into_iter()
            .find(|e| e.name == name_str)
            .map(|e| e.working_copy_id)
            .ok_or(PumpError::LandingTargetMissing {
                workspace: name_str,
                issue_id,
            })
    }

    /// Persist an `active_workers` row for a worker being spawned (#2).
    ///
    /// Written when the worker is spawned and removed on every completion /
    /// cleanup path ([`remove_worker`](Self::remove_worker)). The row carries
    /// the stable per-attempt `worker_uuid`, the issue, role, round, and
    /// workspace path. `pid` is `None`: workers are hosted through the `zellij`
    /// CLI, which exposes no per-pane OS pid (REQ-1d), so P1 has no pid to
    /// persist — a real pid + process-group kill is deferred to #16 P2. The row
    /// itself is what P2 recovery needs; **P1 does not read it back to recover a
    /// crashed worker** (it only persists it).
    fn register_worker(
        &self,
        key: &str,
        worker_uuid: &str,
        round: u32,
        workspace_path: &std::path::Path,
    ) -> Result<(), PumpError> {
        let now = now_unix();
        self.state.upsert_worker(&ActiveWorkerRow {
            worker_uuid: worker_uuid.to_owned(),
            issue_id: key.to_owned(),
            role: WorkerRole::Implementer,
            round: round as i64,
            workspace_path: workspace_path.to_path_buf(),
            pid: None,
            spawned_at: now,
            last_heartbeat: now,
        })?;
        Ok(())
    }

    /// Best-effort removal of a worker's `active_workers` row on terminal
    /// completion or cleanup (#2). A failure to delete the bookkeeping row must
    /// not itself fail the tick, so the error is swallowed.
    fn remove_worker(&self, worker_uuid: &str) {
        let _ = self.state.remove_worker(worker_uuid);
    }

    /// The current round for an issue (0 if it has no state row yet).
    fn current_round(&self, key: &str) -> Result<u32, PumpError> {
        Ok(self
            .state
            .get_issue(key)?
            .map(|i| i.round.max(0) as u32)
            .unwrap_or(0))
    }

    /// Poison an issue: set `phase:orchestrator-error`, mirror the label, emit,
    /// and clean up its workspace. The terminal fault state (REQ error-handling).
    fn poison(
        &self,
        key: &str,
        name: &WorkspaceName,
        reason: &str,
    ) -> Result<IssueOutcome, PumpError> {
        // Best-effort workspace cleanup — a poison must not leak the workspace.
        let _ = self.manager.forget(name);
        let from = self
            .state
            .get_issue(key)?
            .map(|i| i.phase)
            .unwrap_or(Phase::Implementing);
        self.state.set_phase(key, Phase::OrchestratorError, None)?;
        if let Ok(id) = key.parse::<i64>() {
            self.set_phase_label(id, Phase::OrchestratorError)?;
        }
        emit(
            &self.state,
            &self.log,
            EventKind::Transition,
            Some(key),
            None,
            &json!({
                "from_phase": from.as_str(),
                "to_phase": Phase::OrchestratorError.as_str(),
                "reason": reason,
            }),
        )?;
        Ok(IssueOutcome::OrchestratorError)
    }

    /// Advance an issue's authoritative phase (`state.db`), mirror the `phase:*`
    /// label to crosslink (presentation), and emit the transition event.
    fn transition(&self, key: &str, from: Phase, to: Phase, reason: &str) -> Result<(), PumpError> {
        self.state.set_phase(key, to, None)?;
        if let Ok(id) = key.parse::<i64>() {
            self.set_phase_label(id, to)?;
        }
        emit(
            &self.state,
            &self.log,
            EventKind::Transition,
            Some(key),
            None,
            &json!({
                "from_phase": from.as_str(),
                "to_phase": to.as_str(),
                "reason": reason,
            }),
        )?;
        Ok(())
    }

    /// Mirror the authoritative phase onto crosslink's `phase:*` label set
    /// (REQ-2 presentation): remove every other `phase:*` label and add the one
    /// for `phase`. Idempotent — a label already present is a no-op.
    fn set_phase_label(&self, issue_id: i64, phase: Phase) -> Result<(), PumpError> {
        let want = format!("{PHASE_LABEL_PREFIX}{}", phase.as_str());
        // Read the current label set so stale `phase:*` labels are removed.
        let info = self.crosslink.read_issue(issue_id)?;
        for label in &info.labels {
            if label.starts_with(PHASE_LABEL_PREFIX) && label != &want {
                self.crosslink.label_remove(issue_id, label)?;
            }
        }
        self.crosslink.label_add(issue_id, &want)?;
        Ok(())
    }

    /// Translate a worker's verified artifacts into crosslink comments,
    /// idempotently against the `posted_artifacts` ledger (REQ-3, REQ-3b).
    ///
    /// Each planned comment is posted at most once: the `(worker_uuid,
    /// artifact_path, content_sha, finding_index)` tuple is checked against the
    /// ledger first; a tuple already recorded is skipped (crash-replay safe).
    fn translate_artifacts(
        &self,
        issue_id: i64,
        worker_uuid: &str,
        done: &DoneSentinel,
    ) -> Result<(), PumpError> {
        let set = ArtifactSet { done: done.clone() };
        let plan = crate::artifacts::translation_plan(worker_uuid, &set)?;
        for item in plan {
            if self.state.is_posted(
                worker_uuid,
                &item.artifact_path,
                &item.content_sha,
                item.finding_index,
            )? {
                continue;
            }
            let comment_id = self.crosslink.comment_write(
                issue_id,
                item.kind.as_str(),
                &item.body,
                Some(WORKER_ROLE_TAG),
            )?;
            self.state.record_posted(&crate::state::PostedArtifact {
                worker_uuid: worker_uuid.to_owned(),
                artifact_path: item.artifact_path,
                content_sha: item.content_sha,
                finding_index: item.finding_index,
                comment_id: comment_id.to_string(),
                posted_at: now_unix(),
            })?;
        }
        Ok(())
    }
}

/// The orchestrator-private directory holding `state.db` and `events.jsonl`,
/// relative to the repository root. Re-exported shape for the pump's callers.
pub const ORCHESTRATOR_DIR: &str = ".orchestrator";

/// The `state.db` path under the orchestrator directory.
pub fn state_db_path(root: &std::path::Path) -> PathBuf {
    root.join(ORCHESTRATOR_DIR).join("state.db")
}

/// Current time as unix seconds (0 before the epoch, never panics) — the
/// `posted_at` stamp for the idempotency ledger.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_outcome_terminality() {
        assert!(IssueOutcome::Merged.is_terminal());
        assert!(IssueOutcome::AwaitingHumanMerge.is_terminal());
        assert!(IssueOutcome::OrchestratorError.is_terminal());
        assert!(
            !IssueOutcome::Requeued.is_terminal(),
            "requeue is re-driven"
        );
    }

    #[test]
    fn state_db_path_is_under_orchestrator_dir() {
        let p = state_db_path(std::path::Path::new("/repo"));
        assert!(p.ends_with(".orchestrator/state.db"));
    }
}
