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
//! # The per-issue state machine (iteration 2: adversary review → converge → land)
//!
//! ```text
//!   graphed
//!     └─ label phase:implementing, prepare workspace on `main`,
//!        spawn the Implementer, wait
//!          └─ verify DONE (S3)  ── missing ─▶ orchestrator-error (crash)
//!             └─ translate artifacts → crosslink comments (idempotent, REQ-3b)
//!                └─ qa-gate (S5): QaGate::run()
//!                     ├─ Pass ─▶ adversary-review (A2): render diff/log/prior-
//!                     │            findings, spawn Adversary, verify DONE, read
//!                     │            findings with the STRICT Findings::from_done
//!                     │            ├─ findings ─▶ post blockers, round++, back to
//!                     │            │               implementing (findings as input,
//!                     │            │               REQ-8); re-implement in-process
//!                     │            └─ clean round ─▶ converged? (A3: N clean
//!                     │                  rounds, empty_round_streak >= n_rounds, default 2)
//!                     │                  ├─ yes ─▶ converged → landing (L2)
//!                     │                  │           ├─ Merged / AwaitingHumanMerge
//!                     │                  └─ no  ─▶ re-review same change, fresh Adversary
//!                     ├─ Fail ─▶ blocker comment + back to implementing
//!                     │           (bounded retries; requeued across ticks)
//!                     └─ Err(poison) ─▶ orchestrator-error
//! ```
//!
//! The convergence rule is now *QA pass → adversary review → (findings ?
//! re-implement : clean round → converge) → land* (A2, #22). Two loops:
//!
//! - **QA fail** re-implements **across ticks**: it posts a blocker, bumps the
//!   round, and re-queues at `Implementing` **in `state.db`**; the next tick's
//!   drive step re-selects it (the label is already off `phase:graphed`) and
//!   re-spawns. Bounded by [`MAX_QA_RETRIES`].
//! - **Adversary findings** re-implement **in-process**: findings are posted as
//!   `--kind blocker`s, accumulated, and rendered into the next round's inputs
//!   (REQ-8 fresh context — the Adversary's `prior_findings.json` and the
//!   Implementer's task), so the whole implement→review cycle runs inside one
//!   `drive_issue` call. Bounded by [`MAX_ADVERSARY_ROUNDS`].
//!
//! A **clean round** is read with the strict [`crate::artifacts::Findings::from_done`]:
//! it REQUIRES a DONE-attested `findings.jsonl`, so an Adversary that wrote DONE
//! but no findings is an *incomplete* review (poisoned), never a false
//! convergence. Convergence (A3, #23) is the REQ-10 detector: **N consecutive
//! clean Adversary rounds on the SAME change** — each clean round below the
//! threshold re-spawns a FRESH Adversary on the same committed change (fresh
//! context may catch what the prior missed), and `empty_round_streak` climbs by
//! one per clean re-review round. Because the change is resolved to an immutable
//! jj commit id for the whole review, it cannot move between rounds, so the
//! streak alone captures "N consecutive clean rounds"; REQ-10's `last_diff_hash`
//! stability condition is vestigial in this synchronous model (it would matter
//! only if the change could move mid-review — a concurrent landing or a future
//! async model — a documented follow-up, not faked here). `[convergence]
//! n_rounds` (default 2, validated into `1..=MAX_ADVERSARY_ROUNDS` at config
//! load) sets N; the dogfoods pin it to 1 so they land on their first clean
//! round. The whole rule lives behind the [`BuildPump::converged`] +
//! [`BuildPump::on_clean_round`] seam.
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
//! # Known limitation: the review loop blocks the tick (single-orchestrator)
//!
//! [`drive_issue`](BuildPump::drive_issue) runs an issue's whole
//! implement→review→(re-implement|converge)→land machine **synchronously**, so
//! the in-process adversary loop (each of up to [`MAX_ADVERSARY_ROUNDS`] rounds
//! spawns a worker and waits for it) holds the tick for that issue's entire
//! review. A single tick therefore *starts* at most `max_concurrent_agents`
//! issues but does not interleave their reviews: raising the budget above 1 buys
//! no concurrency *within* one issue's review. This is an intentional property of
//! the single-orchestrator, single-`state.db`-writer model (REQ-2, REQ-3), not a
//! bug — concurrency across *distinct* issues is the budget's job; concurrency
//! *within* one issue's review is out of scope here (a future async/worker-pool
//! reactor would be the place for it, and is deliberately not built now).
//!
//! # No shell-out (AC-24)
//!
//! The pump constructs no `std::process::Command`. Its worker runs as a
//! `WorkerCommand::Direct` through the `Spawner` (zellij-hosted); its QA runs
//! `bash static_qa.sh` through [`QaGate`] (the sanctioned exception); its jj
//! work goes through the [`WorkspaceManager`] gate; and crosslink is reached only
//! through [`CrosslinkRepo`]. There is no `unwrap`/`panic` on any non-test path.

#![allow(clippy::result_large_err)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use miette::Diagnostic;
use serde_json::json;
use thiserror::Error;
use uuid::Uuid;
use vetinari_crosslink_api::CrosslinkRepo;

use crate::artifacts::{
    ArtifactSet, CommentKind, DoneSentinel, Finding, Findings, Location, Severity,
};
use crate::config::{OrchestratorConfig, WorkerKind};
use crate::events::{emit, EventLog};
use crate::landing::{
    branch_name, land_local, land_remote, retry_land_after_merge, LandingOutcome, OctocrabPrOpener,
    RemoteLanding, MAIN_BOOKMARK,
};
use crate::qa::{QaGate, QaOutcome, QaSandbox};
use crate::roles::adversary::{render_inputs, RenderParams, RenderedAdversaryInputs};
use crate::roles::merger::{render_conflict_input, ConflictContext};
use crate::spawn::{SandboxHost, SpawnOutcome, Spawner, WorkerCommand};
use crate::state::{
    ActiveWorkerRow, EventKind, IssueRow, Phase, PhaseSubstate, StateDb, WorkerRole,
};
use crate::workspace::{WorkspaceManager, WorkspaceName};

/// The crosslink label prefix the pump moves as it advances an issue (REQ-2:
/// presentation only). `phase:<phase-token>`, where the token is the same one
/// `state.db` stores (e.g. `phase:graphed`, `phase:merged`).
pub const PHASE_LABEL_PREFIX: &str = "phase:";

/// The label the build pump picks up on: open issues carrying it are the pump's
/// work queue (Q1 strict policy — unphased issues are ignored).
pub const GRAPHED_LABEL: &str = "phase:graphed";

/// The explicit human trust-gate label that authorizes an `xb:inbound`
/// (untrusted-origin) issue to land (REQ-SWARM-1, spec §1.2).
///
/// A converged inbound issue parks at [`Phase::AwaitingInboundApproval`] and is
/// **never** auto-landed — in *either* `tracker_remote` mode, regardless of any
/// `auto_graph` policy — because its origin peer is derived from a socket path,
/// not authenticated (the threat model's "untrusted origin ⇒ HARD NO-GO on
/// auto-land", which the QA sandbox does not lift for intent-level T2/T4 attacks).
/// A human adds this label after reviewing the work; the pump's approval sweep
/// ([`BuildPump::resume_approved_inbound`]) then re-drives the parked issue into
/// landing, mirroring the `AwaitingHumanMerge` label-gated resume (REQ-15a).
/// Locally-authored issues never carry `xb:inbound`, so this gate never touches
/// them.
pub const INBOUND_APPROVED_LABEL: &str = "inbound-approved:land";

/// The role attribution recorded on translated crosslink comments (AC-16). The
/// worker is the fake/real Implementer; the pump posts on its behalf.
pub const WORKER_ROLE_TAG: &str = "implementer";

/// The role attribution recorded on Adversary-derived crosslink comments
/// (AC-16): the Adversary's findings (`--kind blocker`) and review summary are
/// posted by the pump on the Adversary's behalf, so they are attributed to it,
/// not to the Implementer.
pub const ADVERSARY_ROLE_TAG: &str = "adversary";

/// The role attribution recorded on Merger-derived crosslink comments (AC-16):
/// the conflict-context blocker posted when a landing parks for a human merge
/// (and, in a later iteration, the `--kind resolution` summary) is attributed to
/// the Merger, not the Implementer.
pub const MERGER_ROLE_TAG: &str = "merger";

/// The role attribution recorded on the inbound approval-gate blocker (AC-16):
/// the "parked for human approval" blocker a converged `xb:inbound` issue carries
/// (REQ-SWARM-1) is posted by the orchestrator itself on behalf of the crossbridge
/// trust boundary, not by any worker.
pub const INBOUND_ROLE_TAG: &str = "crossbridge";

/// The base revset a fresh worker workspace is rooted on: `main`, so the
/// worker's change is a child of trunk and lands as a clean fast-forward
/// (REQ-17 local path).
pub const WORKER_BASE_REVSET: &str = "main";

/// How many times QA may fail-and-re-spawn before the pump gives up and parks
/// the issue at `orchestrator-error`. The MVP fixture passes first try; this
/// bounds a genuinely-failing worker so the pump can't loop forever.
pub const MAX_QA_RETRIES: i64 = 3;

/// How many implement→review rounds an issue may go through before the pump
/// gives up and parks it at `orchestrator-error` (A2). Each Adversary round that
/// reports findings bumps the round and re-implements; without a bound an issue
/// the Adversary never signs off on would loop forever. The MVP fixtures
/// converge within one or two rounds; this only trips a genuinely-diverging
/// issue.
pub const MAX_ADVERSARY_ROUNDS: i64 = 6;

/// How many Merger workers may be spawned per issue before the pump gives up and
/// parks at `phase:awaiting-human-merge` (REQ-19, Q5: **one** Merger retry only).
/// The Merger had full, fresh conflict context; repeating it almost certainly
/// wastes inference, so a single failed attempt parks for a human (REQ-15a).
/// Bounds the `landing_retry_count` column.
pub const MAX_MERGER_SPAWNS: i64 = 1;

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

    /// A crossbridge adapter operation failed — deriving this node's own slug
    /// when the embedded server is enabled (spec §1.3). A `SubmitAnswer` *wire*
    /// failure is NOT this: it is handled in-band by the answer state machine
    /// (`answer_unreachable`), never propagated as a tick-aborting `PumpError`.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Crossbridge(#[from] vetinari_crossbridge_api::CrossbridgeError),

    /// A worker artifact could not be verified or translated.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Artifact(#[from] vetinari_error::ArtifactError),

    /// Pre-rendering an Adversary worker's inputs (diff/log/prior-findings/task)
    /// failed (REQ-8, A1).
    #[error(transparent)]
    #[diagnostic(transparent)]
    Adversary(#[from] vetinari_error::AdversaryError),

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

    /// The `main` bookmark did not resolve while rendering a Merger's
    /// `conflict.md` (REQ-19). Landing only reaches the Merger path from a repo
    /// whose `main` exists, so an unset `main` here is a corrupt state — surfaced
    /// explicitly rather than silently rendered as a blank target field.
    #[error(
        "the `main` bookmark did not resolve while preparing the Merger conflict input for \
         issue #{issue_id} — cannot render conflict.md against an unknown target"
    )]
    #[diagnostic(code(vetinari::pump::main_bookmark_unresolved))]
    MainBookmarkUnresolved {
        /// The issue whose conflict input was being rendered.
        issue_id: i64,
    },

    /// Delivering the accumulated Adversary findings into a re-implement round's
    /// Implementer workspace (REQ-8) failed — the pre-spawn
    /// `_orchestrator/prior_findings.jsonl` input could not be written.
    #[error("failed to deliver prior findings to the Implementer workspace `{workspace}`")]
    #[diagnostic(code(vetinari::pump::prior_findings_delivery))]
    PriorFindings {
        /// The Implementer workspace whose prior-findings input write failed.
        workspace: PathBuf,
        /// Underlying I/O (or serialization) error.
        #[source]
        source: std::io::Error,
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
    /// The issue reached `phase:pr-open` — landed remotely (branch pushed, PR
    /// opened, REQ-17 remote path).
    PrOpen,
    /// The issue is parked at `phase:awaiting-human-merge` — a landing conflict a
    /// Merger could not resolve (missing DONE, unresolved conflict, post-merge QA
    /// fail, or a non-fast-forward retry), or a non-fast-forward bookmark move
    /// (REQ-19, REQ-15a).
    AwaitingHumanMerge,
    /// A converged `xb:inbound` (untrusted-origin) issue was parked at
    /// `phase:awaiting-inbound-approval` by the inbound trust-gate instead of
    /// landing (REQ-SWARM-1). It stays parked — in either `tracker_remote` mode —
    /// until a human adds `inbound-approved:land`, which resumes it into landing.
    AwaitingInboundApproval,
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

    /// Build the **sandboxed** static QA gate for `workspace` (P0: closes T1).
    ///
    /// The gate runs the worker's `static_qa.sh` — which compiles and runs
    /// worker-authored `build.rs`/test code — inside a hermetic, network-denied
    /// bwrap namespace, never bare on the host. The sandbox reuses the exact
    /// machinery the pump's [`Spawner`] already owns: the spawner's verified
    /// [`crate::spawn::SandboxPin`] and a [`SandboxHost`] resolved from it. The
    /// host is resolved here (once, at gate construction) rather than deep inside
    /// [`QaGate::run`]; the store-path pin is re-verified fail-closed inside
    /// `run` immediately before the child spawns.
    ///
    /// Resolving the host can fail on a misconfigured environment (`$HOME` unset)
    /// — that is a host/orchestrator error, surfaced as [`PumpError::Spawn`],
    /// never a silent unsandboxed fallback. QA uses
    /// [`SandboxHost::resolve_for_qa`], which resolves only the fields
    /// [`SandboxHost::qa_mounts`] consumes (no `nix-shell`, no creds overlay), so
    /// the gate does not inherit the worker path's `nix-shell` dependency for a
    /// binary QA never invokes.
    fn qa_gate(&self, workspace: &Path) -> Result<QaGate, PumpError> {
        let pin = self.spawner.pin().clone();
        let host = SandboxHost::resolve_for_qa(&pin)?;
        Ok(
            QaGate::new(workspace, QaSandbox::new(host, pin))
                .with_timeout(self.config.qa_timeout()),
        )
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
            // Answer-back trigger (spec §1.3): the moment an issue reaches a
            // terminal phase, if it is `xb:inbound` arm it for answer delivery.
            // A no-op for every locally-authored issue (the trigger reads the
            // crosslink labels and leaves non-inbound issues untouched), and only
            // consulted at all when the embedded crossbridge server is enabled.
            if self.config.crossbridge.enabled && outcome.is_terminal() {
                crate::answer::on_issue_terminal(
                    &self.state,
                    &self.crosslink,
                    &self.log,
                    issue_id,
                )?;
            }
            outcomes.push((issue_id, outcome));
        }

        // Step 2b — inbound approval resume (REQ-SWARM-1): re-drive any `xb:inbound`
        // issue parked at `awaiting-inbound-approval` that a human has now labeled
        // `inbound-approved:land` into landing, from its durably-stored reviewed
        // change. The parked phase is terminal + non-drivable, so the drive step
        // above never re-selects it — this label-gated sweep is its only resume,
        // mirroring the `AwaitingHumanMerge` resume model (REQ-15a).
        let mut resumed = self.resume_approved_inbound()?;
        outcomes.append(&mut resumed);

        // Step 3 — answer sweep (spec §1.3): deliver any inbound issue awaiting
        // an answer, and retry the degraded `answer_unreachable` ones (bounded,
        // rate-limited). Gated on the embedded server being enabled, so a
        // crossbridge-unaware node does exactly nothing here.
        if self.config.crossbridge.enabled {
            self.sweep_answers()?;
        }
        Ok(outcomes)
    }

    /// Deliver pending crossbridge answers for terminal inbound issues (spec
    /// §1.3), resolving this node's slug + socket root from config the same way
    /// `main::start_crossbridge` does. Errors from the wire round-trip are handled
    /// in-band by the state machine; only a slug-derivation / state.db / crosslink
    /// fault surfaces as a `PumpError`.
    fn sweep_answers(&self) -> Result<(), PumpError> {
        let own_slug = vetinari_crossbridge_api::own_slug(
            self.manager.root(),
            self.config.crossbridge.slug.as_deref(),
        )?;
        let socket_root = self
            .config
            .crossbridge
            .socket_root
            .clone()
            .unwrap_or_else(vetinari_crossbridge_api::default_socket_root);
        let retry_interval = self.config.crossbridge.answer_retry_interval_s as i64;
        crate::answer::deliver_pending(
            &self.state,
            &self.crosslink,
            &self.log,
            &crate::answer::CrossbridgeTransport,
            &own_slug,
            &socket_root,
            retry_interval,
            now_unix(),
        )?;
        Ok(())
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

    // --- inbound approval resume (REQ-SWARM-1) ------------------------------

    /// Re-drive every `xb:inbound` issue parked at `awaiting-inbound-approval`
    /// that a human has now approved with the [`INBOUND_APPROVED_LABEL`] label,
    /// landing it (spec §1.2, REQ-SWARM-1).
    ///
    /// This is the label-gated resume that mirrors the `AwaitingHumanMerge` model:
    /// the parked phase is terminal and NOT drivable, so the drive step never
    /// re-selects it; instead this sweep scans `state.db` for parked inbound issues
    /// and, for each one whose crosslink labels now carry `inbound-approved:land`,
    /// lands **exactly the reviewed change** it converged on — read back from the
    /// durable `landing_change` handle the park stored ([`park_for_inbound_approval`]
    /// (Self::park_for_inbound_approval)), never a fresh re-implementation the human
    /// did not approve. Re-entering [`land`](Self::land) now falls straight through
    /// the gate (the approval label is present) into the normal landing path, in
    /// whichever `tracker_remote` mode is configured.
    ///
    /// Deliberately **not** gated on `[crossbridge] enabled`: an approval a human
    /// applied must always be honored, even against a stale parked issue on a node
    /// whose crossbridge server is currently disabled.
    ///
    /// # Answer exactly once across `park → approve → merge`
    ///
    /// The source peer must be answered **exactly once**, whenever delivery actually
    /// succeeds. The FIRST terminal an inbound issue reaches — the approval park
    /// (spec §1.3) — arms the answer via the drive loop's terminal trigger in
    /// [`tick`](Self::tick), and the step-3 sweep tries to deliver it. Two cases
    /// diverge when this resume then lands the approved change (landing clears
    /// `phase_substate` to `None` on the merge terminal, which the answer sweep keys
    /// entirely off):
    ///
    /// - **Park answer already delivered (`answer_sent`).** The peer has its result;
    ///   nothing more is owed. This path therefore does **not** re-fire
    ///   [`crate::answer::on_issue_terminal`] and does **not** re-arm — re-arming
    ///   would defeat the answer machine's "already in an answer substate" guard and
    ///   send a SECOND delivery. Not re-arming is the structural guarantee of "at
    ///   most once".
    /// - **Park answer never delivered (`answer_pending` / `answer_unreachable`).**
    ///   The peer was offline during the approval window, so the merge just erased
    ///   the very substate the retry sweep needs — silently degrading "answer at most
    ///   once" into "answer zero times". So before landing we capture whether the
    ///   answer is still undelivered, and after the land clears the substate we
    ///   **re-arm `answer_pending`** (preserving the existing `answer_attempts` retry
    ///   bookkeeping) so the step-3 sweep delivers it now, at the merge terminal.
    ///
    /// Re-firing `on_issue_terminal` is deliberately still avoided in BOTH cases: the
    /// re-arm is an explicit, substate-conditioned `answer_pending` write, not the
    /// unconditional trigger, so the `answer_sent` case is never disturbed.
    ///
    /// A parked issue with no stored `landing_change` (an impossible state the park
    /// always writes, guarded here defensively) is left parked rather than landed
    /// from a guessed target. Returns the `(issue_id, outcome)` for each issue this
    /// sweep resumed.
    fn resume_approved_inbound(&self) -> Result<Vec<(i64, IssueOutcome)>, PumpError> {
        let mut outcomes = Vec::new();
        for row in self.state.list_issues()? {
            if row.phase != Phase::AwaitingInboundApproval {
                continue;
            }
            let Ok(issue_id) = row.issue_id.parse::<i64>() else {
                continue;
            };
            let info = self.crosslink.read_issue(issue_id)?;
            if !has_label(&info.labels, INBOUND_APPROVED_LABEL) {
                // Still parked: no human approval yet. Leave it exactly as is.
                continue;
            }
            let Some(change) = row.landing_change.clone() else {
                // Defensive: the park always persists the reviewed change before
                // flipping the phase, so this should be unreachable. If it ever
                // happens, refuse to land from a guessed target — stay parked.
                emit(
                    &self.state,
                    &self.log,
                    EventKind::Transition,
                    Some(&row.issue_id),
                    None,
                    &json!({
                        "inbound_approval": "resume_skipped",
                        "reason": "approved but no stored landing_change — cannot resume; staying parked",
                    }),
                )?;
                continue;
            };
            // Capture whether the peer's park-time answer is STILL undelivered
            // BEFORE the land clears `phase_substate` on the merge terminal. Only a
            // not-yet-delivered answer (`answer_pending`/`answer_unreachable`) is an
            // outstanding obligation; `answer_sent` is already done and must never be
            // re-armed (that would be a second delivery). See this method's doc.
            let answer_still_owed = matches!(
                row.phase_substate
                    .as_deref()
                    .and_then(PhaseSubstate::from_db_str),
                Some(PhaseSubstate::AnswerPending | PhaseSubstate::AnswerUnreachable)
            );

            // Land exactly the reviewed change. The answer-back TRIGGER
            // (`on_issue_terminal`) is deliberately NOT fired here — see this
            // method's doc; the re-arm below is the narrow, substate-conditioned
            // replacement that leaves an already-`answer_sent` issue untouched.
            let outcome = self.land(issue_id, &row.issue_id, &change)?;

            if answer_still_owed {
                // The merge wiped the `answer_unreachable`/`answer_pending` substate
                // the retry sweep keys off, so the peer would otherwise be answered
                // ZERO times. Re-arm `answer_pending` (a plain substate write —
                // `answer_attempts` is preserved, so the retry bound still holds) so
                // the step-3 sweep in this same tick delivers it, now that the issue
                // has reached its merge terminal.
                self.state
                    .set_phase_substate(&row.issue_id, Some(PhaseSubstate::AnswerPending))?;
                emit(
                    &self.state,
                    &self.log,
                    EventKind::Transition,
                    Some(&row.issue_id),
                    None,
                    &json!({
                        "answer": "re_armed_pending",
                        "reason": "park-time answer was never delivered (peer offline); \
                                   merge cleared the substate — re-arm so the peer is \
                                   answered exactly once at the merge terminal",
                    }),
                )?;
            }
            outcomes.push((issue_id, outcome));
        }
        Ok(outcomes)
    }

    // --- per-issue state machine --------------------------------------------

    /// Drive one drivable `state.db` issue to a terminal-or-requeued phase.
    ///
    /// The caller ([`tick`](Self::tick)) selected this issue from `state.db`
    /// (never a label). This runs the full iteration-2 loop for the issue:
    ///
    /// ```text
    ///   implement → QA → adversary-review
    ///                       ├─ findings   → re-implement (round++, findings as input)
    ///                       └─ clean round → converge? → land : re-review
    /// ```
    ///
    /// The **re-implement-on-findings** cycle runs in-process: when the Adversary
    /// reports findings the pump posts them as `--kind blocker` comments, bumps
    /// the round, and loops back to spawn a fresh Implementer whose task carries
    /// the accumulated findings (REQ-8 fresh context, threaded through the local
    /// `prior_findings` accumulator). That accumulator is **seeded on entry** from
    /// the durable blocker comments ([`rehydrate_prior_findings`](Self::rehydrate_prior_findings)),
    /// so a crash mid-review (recovery rolls the issue back to `implementing`)
    /// does not make the re-implement blind. The **QA-fail** re-implement path is
    /// unchanged: it still returns [`IssueOutcome::Requeued`] so the next tick
    /// re-drives it from `state.db` (its own bounded retry). Every phase
    /// transition writes `state.db` (the authority), mirrors the `phase:*` label
    /// (presentation), and emits an event (REQ-14).
    ///
    /// While a worker is in flight an `active_workers` row is persisted (#2) so
    /// the `posted_artifacts` ledger (REQ-3b) has a stable identity and P2's
    /// crash-recovery (#16) has the state it needs; the row is removed on every
    /// completion/cleanup path.
    fn drive_issue(&self, issue_id: i64) -> Result<IssueOutcome, PumpError> {
        let key = issue_id.to_string();

        // graphed/implementing → implementing: the `from` phase is read from
        // state.db (authority) so a requeued issue's event reads
        // `implementing→implementing`, not a fabricated `graphed→…`.
        let from = self
            .state
            .get_issue(&key)?
            .map(|i| i.phase)
            .unwrap_or(Phase::Graphed);
        self.transition(&key, from, Phase::Implementing, "build pump pickup")?;

        // Findings accumulate across in-process re-implement rounds and are
        // rendered into every subsequent Adversary's `prior_findings.json` AND
        // the fresh Implementer's task (REQ-8) — never carried as agent memory.
        //
        // The accumulator is SEEDED from the durable `--kind blocker` comments
        // the Adversary's findings were posted as (#2): a crash mid-review
        // rolls the issue back to `implementing` (recovery) and drops the
        // in-memory accumulator, so re-hydrating it here keeps the re-implement
        // round from re-implementing BLIND while the persisted `round` climbs
        // toward the poison cap. On a first (non-crash) entry there are no
        // blockers yet, so this is `[]` and the in-process loop fills it.
        let mut prior_findings: Vec<Finding> = self.rehydrate_prior_findings(issue_id)?;
        loop {
            // === implement → QA for the current round ===
            let name = match self.run_implementer_round(issue_id, &key, &prior_findings)? {
                ImplStep::Done(outcome) => return Ok(outcome),
                ImplStep::QaPassed { name } => name,
            };

            // === adversary review (may re-implement or converge+land) ===
            match self.run_adversary_review(issue_id, &key, &name, &mut prior_findings)? {
                ReviewStep::Done(outcome) => return Ok(outcome),
                ReviewStep::Reimplement => {
                    // Findings posted, round bumped, phase rolled back to
                    // implementing: loop and spawn a fresh Implementer.
                    continue;
                }
            }
        }
    }

    /// Run one Implementer round: prepare a fresh workspace, spawn the worker,
    /// verify DONE, translate artifacts, guard the empty commit, and run QA.
    ///
    /// Returns [`ImplStep::QaPassed`] with the prepared workspace + name when QA
    /// passes (the caller then runs adversary review on that change), or
    /// [`ImplStep::Done`] carrying the terminal/requeue outcome for every other
    /// path (missing DONE → poison, empty change → poison, QA fail → requeue, QA
    /// poison → poison). The phase is assumed to already be `Implementing` on
    /// entry (the caller transitioned it); this emits `implementing → qa-gate`.
    ///
    /// `prior_findings` is threaded to [`worker_command`](Self::worker_command)
    /// so a re-implement round's Implementer receives the accumulated Adversary
    /// findings as task input (REQ-8).
    fn run_implementer_round(
        &self,
        issue_id: i64,
        key: &str,
        prior_findings: &[Finding],
    ) -> Result<ImplStep, PumpError> {
        let round = self.current_round(key)?;
        // Reset `empty_round_streak` on every Implementer (re-)spawn (the
        // schema's reset rule (c)): a fresh implementation invalidates any clean
        // Adversary rounds counted against the PRIOR implementation, so a stale
        // streak can never fool A3's n-rounds convergence detector into landing
        // a re-implemented change on carried-over clean rounds. A no-op write
        // when the streak is already 0 (the common first-round case).
        if let Some(mut issue) = self.state.get_issue(key)? {
            if issue.empty_round_streak != 0 {
                issue.empty_round_streak = 0;
                self.state.upsert_issue(&issue)?;
            }
        }
        let name = WorkspaceName::generate(Phase::Implementing, key, round);
        let prepared = self.manager.prepare(&name, WORKER_BASE_REVSET)?;
        // Deliver the accumulated Adversary findings into the Implementer's
        // workspace (REQ-8) BEFORE the spawn, so a re-implement round's worker
        // reads what it must address as a workspace input — the Direct/generalized
        // worker's findings channel, mirroring the Adversary's pre-rendered
        // `prior_findings.json`. Written on every round (empty on the first), and
        // gitignored so it never lands in the change.
        crate::roles::implementer::render_prior_findings(prepared.path(), prior_findings).map_err(
            |source| PumpError::PriorFindings {
                workspace: prepared.path().to_path_buf(),
                source,
            },
        )?;
        // Mint the worker identity ONCE for this attempt and persist it as an
        // active_workers row (#2): a stable uuid dedupes a re-translation within
        // the run, and the row gives P2 (#16) the state to recover from.
        let worker_uuid = Uuid::new_v4().simple().to_string();
        self.register_worker(
            key,
            &worker_uuid,
            WorkerRole::Implementer,
            round,
            prepared.path(),
        )?;

        let command = self.worker_command(issue_id, prepared.path(), prior_findings)?;
        let handle =
            self.spawner
                .spawn(WorkerRole::Implementer, key, round, &prepared, &command)?;
        emit(
            &self.state,
            &self.log,
            EventKind::Spawn,
            Some(key),
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
            // treated like a crash (REQ-13). Confirm it is gone (#3) before the
            // forget+rm so the cleanup does not race a surviving child.
            let _confirmed_dead =
                handle.close_and_wait(Duration::from_secs(5), Duration::from_millis(200));
            self.remove_worker(&worker_uuid);
            return Ok(ImplStep::Done(self.poison(
                key,
                Some(&name),
                &format!("worker for #{issue_id} exceeded its timeout without exiting"),
            )?));
        }
        // Clean exit: the pane closed itself on command exit (--close-on-exit).
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
                    Some(key),
                    Some(&worker_uuid),
                    &json!({"error": "done_sentinel_missing", "detail": source.to_string()}),
                )?;
                self.remove_worker(&worker_uuid);
                return Ok(ImplStep::Done(self.poison(
                    key,
                    Some(&name),
                    &format!("worker for #{issue_id} left no valid DONE sentinel: {source}"),
                )?));
            }
        };

        // Translate artifacts → crosslink comments (REQ-3, idempotent REQ-3b).
        self.translate_artifacts(issue_id, &worker_uuid, WORKER_ROLE_TAG, &done)?;

        // Empty-commit guard (#4): a worker that wrote a valid DONE but made no
        // change leaves a working copy identical to `main`. Fast-forwarding that
        // would advance `main` to a no-op commit and falsely report Merged.
        if !self
            .manager
            .change_differs_from(WORKER_BASE_REVSET, &self.change_revset(&name, issue_id)?)?
        {
            self.remove_worker(&worker_uuid);
            return Ok(ImplStep::Done(self.poison(
                key,
                Some(&name),
                &format!(
                    "worker for #{issue_id} produced an empty change (no diff vs `{WORKER_BASE_REVSET}`) — refusing to land"
                ),
            )?));
        }

        // qa-gate (S5).
        self.transition(
            key,
            Phase::Implementing,
            Phase::QaGate,
            "worker committed; running QA",
        )?;
        let qa = self.qa_gate(prepared.path())?;
        match qa.run() {
            Ok(QaOutcome::Pass) => {
                emit(
                    &self.state,
                    &self.log,
                    EventKind::QaResult,
                    Some(key),
                    Some(&worker_uuid),
                    &json!({"result": "pass"}),
                )?;
                self.remove_worker(&worker_uuid);
                // The Implementer's committed change is durable in `.jj/`; its
                // WORKSPACE DIR is not needed by adversary review (renders the
                // diff from the change revset) or landing (lands the change
                // revset). `prepared` is dropped here (`PreparedWorkspace` has
                // no `Drop`, so the dir survives) — `run_adversary_review`
                // forgets it explicitly once it has resolved the change (#1).
                drop(prepared);
                Ok(ImplStep::QaPassed { name })
            }
            Ok(QaOutcome::Fail {
                exit_code,
                output_tail,
            }) => {
                emit(
                    &self.state,
                    &self.log,
                    EventKind::QaResult,
                    Some(key),
                    Some(&worker_uuid),
                    &json!({"result": "fail", "exit_code": exit_code}),
                )?;
                self.remove_worker(&worker_uuid);
                Ok(ImplStep::Done(self.on_qa_fail(
                    issue_id,
                    key,
                    &name,
                    exit_code,
                    output_tail.as_str(),
                )?))
            }
            Err(source) => {
                // Poison: a broken/killed/timed-out gate is orchestrator-error,
                // never a blocker (the qa module's load-bearing distinction).
                emit(
                    &self.state,
                    &self.log,
                    EventKind::QaResult,
                    Some(key),
                    Some(&worker_uuid),
                    &json!({"result": "poison", "detail": source.to_string()}),
                )?;
                self.remove_worker(&worker_uuid);
                Ok(ImplStep::Done(self.poison(
                    key,
                    Some(&name),
                    &format!("QA gate for #{issue_id} is broken/poison: {source}"),
                )?))
            }
        }
    }

    /// Run the Adversary review of the Implementer's QA-passed change (A2).
    ///
    /// Spawns a config-selectable Adversary (a Direct fake for deterministic
    /// tests, or a real `claude` Adversary) with the change pre-rendered into its
    /// workspace (REQ-8: the Adversary has no repository `.jj/`, so the
    /// orchestrator renders `diff.patch`/`log.txt`/`prior_findings.json`/`task.md`
    /// on its behalf). A clean round is read with the **strict**
    /// [`Findings::from_done`] — an Adversary that wrote DONE but no
    /// `findings.jsonl` is an incomplete round (poison), NEVER a false
    /// convergence.
    ///
    /// Returns:
    /// - [`ReviewStep::Done`] with a terminal outcome — converged → landed
    ///   (`Merged`/`AwaitingHumanMerge`), or an incomplete/timed-out Adversary
    ///   poisoned, or the round cap tripped;
    /// - [`ReviewStep::Reimplement`] — findings were posted as blockers, the round
    ///   bumped, `empty_round_streak` reset, and the phase rolled back to
    ///   `Implementing`; the caller loops to re-spawn the Implementer.
    fn run_adversary_review(
        &self,
        issue_id: i64,
        key: &str,
        impl_name: &WorkspaceName,
        prior_findings: &mut Vec<Finding>,
    ) -> Result<ReviewStep, PumpError> {
        // The change under review: the Implementer's committed working-copy
        // commit, diffed against its parent (REQ-8, A1). Resolve it to a stable
        // commit id NOW, while the Implementer workspace is still registered,
        // because we forget that workspace immediately below.
        let change = self.change_revset(impl_name, issue_id)?;
        let diff_from = format!("{change}-");
        self.transition(
            key,
            Phase::QaGate,
            Phase::AdversaryReview,
            "QA passed — adversary review",
        )?;

        // #1 (no orphan workspace lingers): forget the Implementer workspace DIR
        // now, before the (multi-round) review window. Its committed change is
        // durable in `.jj/` (non-empty + described ⇒ `workspace forget` does not
        // abandon it), and neither `render_inputs` (renders the diff/log from the
        // change revset) nor `land` (lands the change revset) needs the DIR. So
        // forgetting it here means a crash anywhere in the review can leave NO
        // orphan Implementer workspace — recovery's `AdversaryReview` arm then
        // just rolls the (workspace-less) issue back to `implementing`.
        let _ = self.manager.forget(impl_name);

        // The task the change was meant to accomplish (also handed to a live
        // Adversary; ignored by the Direct fake). Untrusted crosslink input — the
        // orchestrator-side validation, not the worker, protects `main`.
        let info = self.crosslink.read_issue(issue_id)?;
        let task =
            crate::roles::implementer::task_from_issue(&info.title, info.description.as_deref());

        // Adversary rounds on THIS (unchanged) Implementer change: a clean round
        // increments the streak; convergence lands. A findings round breaks out
        // to re-implement. Bounded so a never-converging clean stream can't spin
        // forever.
        for _ in 0..MAX_ADVERSARY_ROUNDS {
            let round = self.current_round(key)?;
            let adv_name = WorkspaceName::generate(Phase::AdversaryReview, key, round);
            let adv_prepared = self.manager.prepare(&adv_name, WORKER_BASE_REVSET)?;
            // Pre-render the Adversary's inputs into its workspace BEFORE the
            // spawn (REQ-8). A render failure is a pump fault, not an issue-level
            // outcome — but clean up both workspaces first so nothing leaks.
            let rendered = match render_inputs(
                &self.manager,
                adv_prepared.path(),
                &RenderParams {
                    diff_from: &diff_from,
                    diff_to: &change,
                    log_revset: &change,
                    prior_findings,
                    task: &task,
                },
            ) {
                Ok(rendered) => rendered,
                Err(source) => {
                    let _ = self.manager.forget(&adv_name);
                    let _ = self.manager.forget(impl_name);
                    return Err(source.into());
                }
            };

            let worker_uuid = Uuid::new_v4().simple().to_string();
            self.register_worker(
                key,
                &worker_uuid,
                WorkerRole::Adversary,
                round,
                adv_prepared.path(),
            )?;
            let command = self.adversary_worker_command(issue_id, &rendered, &task)?;
            let handle =
                self.spawner
                    .spawn(WorkerRole::Adversary, key, round, &adv_prepared, &command)?;
            emit(
                &self.state,
                &self.log,
                EventKind::Spawn,
                Some(key),
                Some(&worker_uuid),
                &json!({
                    "role": ADVERSARY_ROLE_TAG,
                    "round": round,
                    "pane": handle.pane.name.clone(),
                    "workspace": adv_name.as_str(),
                }),
            )?;

            let outcome = handle.wait(self.config.worker_timeout(), Duration::from_millis(300))?;
            if outcome == SpawnOutcome::StillRunning {
                let _dead =
                    handle.close_and_wait(Duration::from_secs(5), Duration::from_millis(200));
                self.remove_worker(&worker_uuid);
                let _ = self.manager.forget(&adv_name);
                return Ok(ReviewStep::Done(self.poison(
                    key,
                    None,
                    &format!("adversary for #{issue_id} exceeded its timeout without exiting"),
                )?));
            }
            handle.close();

            // Verify DONE (S3): a missing/torn sentinel is an incomplete review,
            // handled like any crashed worker — poison, NOT a clean convergence.
            let done = match DoneSentinel::verify(adv_prepared.path()) {
                Ok(done) => done,
                Err(source) => {
                    self.remove_worker(&worker_uuid);
                    let _ = self.manager.forget(&adv_name);
                    return Ok(ReviewStep::Done(self.poison(
                        key,
                        None,
                        &format!("adversary for #{issue_id} left no valid DONE sentinel: {source}"),
                    )?));
                }
            };

            // STRICT convergence read (REQ-10): a clean round REQUIRES a
            // DONE-attested `findings.jsonl`. An absent one is `FindingsMissing`
            // — an incomplete Adversary, poisoned; it must NEVER read as
            // "empty ⇒ converged" (the false-convergence hole A1 closed).
            let findings = match Findings::from_done(&done) {
                Ok(findings) => findings,
                Err(source) => {
                    self.remove_worker(&worker_uuid);
                    let _ = self.manager.forget(&adv_name);
                    return Ok(ReviewStep::Done(self.poison(
                        key,
                        None,
                        &format!(
                            "adversary for #{issue_id} produced no DONE-attested findings.jsonl \
                             ({source}) — treating as an incomplete review, not a clean round"
                        ),
                    )?));
                }
            };
            self.remove_worker(&worker_uuid);

            if !findings.is_empty() {
                // Findings → post each as an idempotent `--kind blocker`
                // (content-addressed ledger dedupes a replay), accumulate them for
                // the next round's inputs, and re-implement (round++).
                self.translate_artifacts(issue_id, &worker_uuid, ADVERSARY_ROLE_TAG, &done)?;
                prior_findings.extend(findings.findings().iter().cloned());
                let finding_count = findings.findings().len();
                // Clean up the Adversary workspace for the finished round (REQ-12).
                // The Implementer workspace was already forgotten before the loop
                // (#1), so nothing else lingers.
                let _ = self.manager.forget(&adv_name);
                return self.on_adversary_findings(issue_id, key, round, finding_count);
            }

            // Clean round: advance the consecutive-clean streak and decide
            // convergence (A3 n-rounds detector). The change under review is a
            // fixed commit id for the whole loop, so a clean re-review round
            // unconditionally counts (see `on_clean_round`).
            let _ = self.manager.forget(&adv_name);
            if self.on_clean_round(key)? {
                self.transition(
                    key,
                    Phase::AdversaryReview,
                    Phase::Converged,
                    "adversary clean; convergence criterion met",
                )?;
                return Ok(ReviewStep::Done(self.land(issue_id, key, &change)?));
            }
            // Not yet converged (A3 n-rounds): re-review the SAME change with a
            // fresh Adversary. Loop.
        }

        // Never converged within the cap — poison rather than loop forever.
        Ok(ReviewStep::Done(self.poison(
            key,
            None,
            &format!(
                "issue #{issue_id} did not converge within {MAX_ADVERSARY_ROUNDS} adversary rounds"
            ),
        )?))
    }

    /// Adversary reported findings: bump the round, reset `empty_round_streak`,
    /// and roll the phase back to `Implementing` so the in-process loop re-spawns
    /// a fresh Implementer (REQ-8). Poisons instead if the round cap is reached.
    ///
    /// The `empty_round_streak = 0` reset is emitted in the event payload so the
    /// reset is observable (the schema's reset rule (a): findings in any round).
    fn on_adversary_findings(
        &self,
        issue_id: i64,
        key: &str,
        round: u32,
        finding_count: usize,
    ) -> Result<ReviewStep, PumpError> {
        let next_round = round as i64 + 1;
        if next_round >= MAX_ADVERSARY_ROUNDS {
            // Nothing to clean: the caller already forgot this round's Adversary
            // workspace, and the Implementer workspace was forgotten before the
            // review loop (#1). Poison WITHOUT a workspace — correct by
            // construction, not by a fabricated-never-prepared name that only
            // no-op'd by accident.
            return Ok(ReviewStep::Done(self.poison(
                key,
                None,
                &format!(
                    "issue #{issue_id} still has adversary findings after {MAX_ADVERSARY_ROUNDS} rounds"
                ),
            )?));
        }
        // Bump round + reset streak in state.db (phase updated to Implementing
        // by the emit below). upsert preserves the row's other columns.
        if let Some(mut issue) = self.state.get_issue(key)? {
            issue.round = next_round;
            issue.empty_round_streak = 0;
            issue.phase_substate = None;
            self.state.upsert_issue(&issue)?;
        }
        // adversary-review → implementing, with the findings + reset in the
        // payload so the re-implement round and streak reset are observable.
        self.state.set_phase(key, Phase::Implementing, None)?;
        self.set_phase_label(issue_id, Phase::Implementing)?;
        emit(
            &self.state,
            &self.log,
            EventKind::Transition,
            Some(key),
            None,
            &json!({
                "from_phase": Phase::AdversaryReview.as_str(),
                "to_phase": Phase::Implementing.as_str(),
                "reason": "adversary findings — re-implementing",
                "findings": finding_count,
                "empty_round_streak": 0,
                "round": next_round,
            }),
        )?;
        // Signal "re-implement" to the caller's loop (which re-preps a fresh
        // Implementer workspace for `next_round`).
        Ok(ReviewStep::Reimplement)
    }

    /// A clean Adversary round (zero findings) on the issue's fixed change:
    /// increment `empty_round_streak`, emit a convergence event, and report
    /// whether the convergence criterion is now met.
    ///
    /// # Why there is no diff-stability comparison here
    ///
    /// REQ-10 frames convergence as *N consecutive clean rounds on the SAME
    /// unchanged change*, historically guarded by matching this round's diff
    /// hash against the prior round's `last_diff_hash`. In THIS synchronous,
    /// single-issue review loop that guard is **vestigial**:
    /// [`run_adversary_review`](Self::run_adversary_review) resolves the
    /// Implementer's change to an **immutable jj commit id once** and re-reviews
    /// that exact id every round, so the diff is byte-identical across clean
    /// rounds *by construction* — the hash could never fail to match, and a
    /// comparison that cannot fail is not protection. So a clean re-review round
    /// **unconditionally increments** the streak; it is reset to 0 only by the
    /// findings / QA-fail / re-implement paths — the sole ways the change under
    /// review can actually change.
    ///
    /// The `last_diff_hash` stability condition would become load-bearing only
    /// if the change could move MID-REVIEW — a concurrent landing, or a future
    /// async worker-pool model where re-review no longer pins one commit id.
    /// That is a **documented follow-up** (REQ-10), NOT something this code
    /// delivers today: the `last_diff_hash` column is retained but unused,
    /// reserved for that model rather than faked here.
    ///
    /// Returns `true` once the streak reaches `[convergence] n_rounds` (computed
    /// once, here, and reused by the caller so `converged` is not recomputed).
    fn on_clean_round(&self, key: &str) -> Result<bool, PumpError> {
        let mut streak = 0;
        if let Some(mut issue) = self.state.get_issue(key)? {
            issue.empty_round_streak += 1;
            streak = issue.empty_round_streak;
            self.state.upsert_issue(&issue)?;
        }
        let converged = self.converged(streak);
        emit(
            &self.state,
            &self.log,
            EventKind::Convergence,
            Some(key),
            None,
            &json!({
                "empty_round_streak": streak,
                "converged": converged,
            }),
        )?;
        Ok(converged)
    }

    /// The convergence detector (REQ-10, A3): an issue has converged once its
    /// `empty_round_streak` reaches the configured `[convergence] n_rounds`.
    ///
    /// The streak counts **consecutive clean Adversary rounds** on the SAME
    /// (immutable-commit-id) change — [`on_clean_round`](Self::on_clean_round)
    /// increments it on every clean re-review round, and every findings /
    /// QA-fail / re-implement path resets it to 0. So this threshold check alone
    /// is the whole n-rounds rule: N fresh clean re-reviews (default N = 2) land
    /// the change; a single clean round no longer suffices unless `n_rounds = 1`
    /// (the dogfood fast path). `n_rounds` is validated at config load to lie in
    /// `1..=MAX_ADVERSARY_ROUNDS`, so this threshold is always reachable and
    /// never zero. `judge`/`human` modes are rejected at config load, so the
    /// mode here is always `n-rounds`.
    fn converged(&self, empty_round_streak: i64) -> bool {
        empty_round_streak >= self.config.convergence.n_rounds as i64
    }

    /// Converged → land the Implementer's committed change (L2) and mirror the
    /// terminal `phase:*` label.
    ///
    /// `change` is the already-resolved commit id of the Implementer's change
    /// (resolved by [`run_adversary_review`](Self::run_adversary_review) while
    /// the Implementer workspace was still registered, then forgotten before the
    /// review — #1). The committed change is durable in `.jj/`, so landing needs
    /// no workspace DIR; there is nothing left to clean up here.
    fn land(&self, issue_id: i64, key: &str, change: &str) -> Result<IssueOutcome, PumpError> {
        // === REQ-SWARM-1: the inbound approval gate (untrusted origin → NEVER auto-land) ===
        //
        // This runs FIRST, before the `tracker_remote` mode-select below, so it
        // covers BOTH landing paths — local fast-forward AND remote push+PR. An
        // `xb:inbound` issue's origin peer is derived from a socket path and is NOT
        // authenticated (REQ-20f); the threat model's verdict on untrusted work is
        // HARD NO-GO on auto-land, and the QA sandbox (P0) does not lift it for the
        // intent-level attacks (T2 deferred payload, T4 prompt-injected gate) that
        // survive it. So a converged inbound issue is parked at
        // `awaiting-inbound-approval` and requires the explicit human
        // `inbound-approved:land` label before it may land — this park is the single
        // structural enforcement point of that boundary, regardless of mode or any
        // `auto_graph` policy.
        //
        // A NON-inbound (locally-authored) issue, or an inbound issue that ALREADY
        // carries `inbound-approved:land` (a human approved it; the approval sweep
        // re-drives it here), falls straight through to land exactly as before.
        //
        // This tracker read now runs for EVERY land, including the local-FF path
        // that was previously tracker-independent (a new coupling; the local land
        // takes one extra crosslink round-trip). A read failure `?`-propagates as a
        // typed [`PumpError`] (never a panic) and ABORTS the land attempt: the issue
        // stays at its current drivable phase to be retried on a later tick — it does
        // NOT fall through the gate (no auto-land) and does NOT park. A transient
        // crosslink hiccup therefore stalls this one land, fail-closed, and never
        // mis-classifies inbound vs. non-inbound.
        let info = self.crosslink.read_issue(issue_id)?;
        if crate::answer::is_inbound(&info.labels)
            && !has_label(&info.labels, INBOUND_APPROVED_LABEL)
        {
            return self.park_for_inbound_approval(issue_id, key, change);
        }

        // Mode gate (REQ-17): crosslink's `tracker_remote` selects local FF vs.
        // remote push+PR. Read at land time (never a compile-time cfg, REQ-2a);
        // empty/unset ⇒ local mode (the default, unchanged).
        //
        // Local mode's `land_local` drives the whole rebase → fast-forward
        // substate machine and owns the Landing/Merged/RebaseConflict/
        // AwaitingHumanMerge transitions; a RebaseConflict is then handled below
        // by dispatching a Merger (REQ-19). Remote mode pushes + opens a PR and
        // never yields a RebaseConflict (conflicts are resolved on GitHub).
        let outcome = match self.crosslink.tracker_remote()? {
            Some(remote) => {
                // Build the PR opener from the SAME remote the branch is pushed to
                // (F3: push target == PR target). A missing GitHub token is an
                // ISSUE-level park, NOT a tick abort (F4): parking this one issue
                // at orchestrator-error lets every other issue in the tick keep
                // progressing, instead of a persistently-missing token bricking
                // the whole pump.
                let opener = match OctocrabPrOpener::for_remote(&self.manager, &remote) {
                    Ok(opener) => opener,
                    Err(vetinari_error::LandingError::GhAuthMissing) => {
                        return self.poison(
                            key,
                            None,
                            &format!(
                                "remote-mode landing for #{issue_id} needs a GitHub token \
                                 (GH_TOKEN or GITHUB_TOKEN) — parking this issue; other issues \
                                 continue"
                            ),
                        );
                    }
                    Err(other) => return Err(other.into()),
                };
                self.land_remote_mode(issue_id, key, change, &remote, &opener)?
            }
            None => land_local(&self.state, &self.log, &self.manager, key, change)?,
        };
        match outcome {
            LandingOutcome::Merged => {
                self.set_phase_label(issue_id, Phase::Merged)?;
                Ok(IssueOutcome::Merged)
            }
            LandingOutcome::PrOpen { .. } => {
                // Landed remotely; mirror the terminal label for the trail.
                self.set_phase_label(issue_id, Phase::PrOpen)?;
                Ok(IssueOutcome::PrOpen)
            }
            LandingOutcome::RebaseConflict { rebased_commit } => {
                // The rebase conflicted (issue now at `Landing/merging`). Dispatch
                // a Merger to resolve it, re-run QA on the merged tree, and retry
                // the fast-forward ONCE (REQ-19, L4). Only a Merger failure falls
                // back to `phase:awaiting-human-merge`.
                self.resolve_conflict_with_merger(issue_id, key, change, &rebased_commit)
            }
            LandingOutcome::AwaitingHumanMerge => {
                // A non-fast-forward move parked directly; mirror the label so the
                // crosslink trail shows the block.
                self.set_phase_label(issue_id, Phase::AwaitingHumanMerge)?;
                Ok(IssueOutcome::AwaitingHumanMerge)
            }
        }
    }

    /// Remote-mode landing (REQ-17 remote path): derive the issue branch, then
    /// drive [`land_remote`] — push the branch and open a GitHub PR through the
    /// [`OctocrabPrOpener`] seam. The title is the reviewed change's description
    /// first line (falling back to the issue title); the body is the issue's
    /// description (the worker's `_orchestrator/result.md` is not retained past
    /// review, so the durable issue text is used).
    fn land_remote_mode(
        &self,
        issue_id: i64,
        key: &str,
        change: &str,
        remote: &str,
        opener: &OctocrabPrOpener,
    ) -> Result<LandingOutcome, PumpError> {
        let info = self.crosslink.read_issue(issue_id)?;
        let branch = branch_name(key, &info.title);
        // Title: the change description's first line, else the issue title.
        let described = self
            .manager
            .resolve_change(change)
            .ok()
            .map(|c| c.description);
        let title = described
            .as_deref()
            .and_then(|d| d.lines().next())
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .unwrap_or(info.title.as_str())
            .to_owned();
        let body = info
            .description
            .clone()
            .unwrap_or_else(|| info.title.clone());
        // The `opener` was built by `land` from the same `remote` (F3) and its
        // GitHub token; a missing-token park already happened there (F4).
        let outcome = land_remote(
            &self.state,
            &self.log,
            &self.manager,
            opener,
            &RemoteLanding {
                issue_id: key,
                change_revset: change,
                remote,
                branch: &branch,
                base: MAIN_BOOKMARK,
                title: &title,
                body: &body,
            },
        )?;
        Ok(outcome)
    }

    /// Test/recovery seam: drive the converged→land step for `issue_id` on the
    /// already-resolved `change_revset`, exercising the full landing path
    /// including the Merger conflict resolution (REQ-19). The issue must already
    /// exist in `state.db`. Public so a landing-conflict integration test can
    /// drive a real Merger `Spawner` + post-merge QA without standing up the
    /// whole implement→review pipeline — mirroring how `land_local`/`resume_from`
    /// are public entry points on the landing machine.
    pub fn land_change(
        &self,
        issue_id: i64,
        change_revset: &str,
    ) -> Result<IssueOutcome, PumpError> {
        self.land(issue_id, &issue_id.to_string(), change_revset)
    }

    /// Resolve a rebase conflict with a Merger worker, then re-run QA and retry
    /// the fast-forward landing ONCE (REQ-19, L4).
    ///
    /// The flow, all fail-safe (never moves `main` sideways):
    ///
    /// 1. **Bound (Q5):** at most [`MAX_MERGER_SPAWNS`] Merger per issue. A second
    ///    conflict after a Merger already ran parks for a human (REQ-15a).
    /// 2. Prepare a fresh workspace **checked out on the conflicted rebase
    ///    result** (`rebased_commit`), so the Merger's files carry the markers,
    ///    and pre-render `_orchestrator/conflict.md` (REQ-19).
    /// 3. Spawn the Merger (Direct fake or real `claude`), wait, verify its DONE
    ///    sentinel. A stall / missing DONE parks for a human.
    /// 4. Read the Merger's resolved working-copy commit. If it **still carries a
    ///    conflict**, the Merger failed → park.
    /// 5. Re-run static QA on the merged tree. A QA fail/poison → park (REQ-19:
    ///    a semantically-broken merge is a Merger failure, AC-21).
    /// 6. Retry the FF landing ONCE via [`retry_land_after_merge`]: a clean FF →
    ///    `phase:merged`; a non-fast-forward → park. Then forget the workspace.
    ///
    /// Every park posts a `--kind blocker` with the conflict context (AC-14) and
    /// mirrors the `phase:awaiting-human-merge` label. The `landing_retry_count`
    /// bump is persisted before the spawn so a crash cannot silently re-spawn an
    /// unbounded number of Mergers.
    fn resolve_conflict_with_merger(
        &self,
        issue_id: i64,
        key: &str,
        change: &str,
        rebased_commit: &str,
    ) -> Result<IssueOutcome, PumpError> {
        // (1) One Merger per issue (Q5). A second conflict parks for a human.
        let retry_count = self
            .state
            .get_issue(key)?
            .map(|i| i.landing_retry_count)
            .unwrap_or(0);
        if retry_count >= MAX_MERGER_SPAWNS {
            return self.park_for_human(
                issue_id,
                key,
                &format!(
                    "rebase for #{issue_id} still conflicts after a Merger attempt — \
                     no further retries (REQ-19)"
                ),
            );
        }
        // Persist the bump BEFORE spawning so a crash cannot re-spawn unbounded.
        if let Some(mut issue) = self.state.get_issue(key)? {
            issue.landing_retry_count = retry_count + 1;
            self.state.upsert_issue(&issue)?;
        }

        let round = self.current_round(key)?;
        // The Merger workspace is named under the Landing phase (there is no
        // dedicated Merger phase); its pane is `merger-<issue>-r<round>`.
        let name = WorkspaceName::generate(Phase::Landing, key, round);
        let prepared = self.manager.prepare(&name, rebased_commit)?;

        // (2) Pre-render conflict.md (REQ-19). The Merger reads it first. `main`
        // must resolve here — landing only reaches this path from a repo with a
        // live `main`; an unset bookmark is a corrupt state, surfaced explicitly
        // (F6) rather than rendered as a mystifying blank target field.
        let target_commit = match self
            .manager
            .bookmark_target(MAIN_BOOKMARK)
            .map_err(PumpError::Landing)?
        {
            Some(commit) => commit,
            None => {
                let _ = self.manager.forget(&name);
                return Err(PumpError::MainBookmarkUnresolved { issue_id });
            }
        };
        let rendered = match render_conflict_input(
            prepared.path(),
            &ConflictContext {
                operation: "rebase onto main",
                target_bookmark: MAIN_BOOKMARK,
                target_commit: &target_commit,
                change_revset: change,
                conflicted_commit: rebased_commit,
            },
        ) {
            Ok(rendered) => rendered,
            Err(source) => {
                let _ = self.manager.forget(&name);
                return Err(source.into());
            }
        };

        // (3) Spawn the Merger and wait.
        let worker_uuid = Uuid::new_v4().simple().to_string();
        self.register_worker(
            key,
            &worker_uuid,
            WorkerRole::Merger,
            round,
            prepared.path(),
        )?;
        let task = "Resolve the rebase conflict described in _orchestrator/conflict.md.";
        let command = self.merger_worker_command(issue_id, &rendered, task)?;
        let handle = self
            .spawner
            .spawn(WorkerRole::Merger, key, round, &prepared, &command)?;
        emit(
            &self.state,
            &self.log,
            EventKind::Spawn,
            Some(key),
            Some(&worker_uuid),
            &json!({
                "role": MERGER_ROLE_TAG,
                "round": round,
                "pane": handle.pane.name.clone(),
                "workspace": name.as_str(),
            }),
        )?;

        let outcome = handle.wait(self.config.worker_timeout(), Duration::from_millis(300))?;
        if outcome == SpawnOutcome::StillRunning {
            let _dead = handle.close_and_wait(Duration::from_secs(5), Duration::from_millis(200));
            self.remove_worker(&worker_uuid);
            let _ = self.manager.forget(&name);
            return self.park_for_human(
                issue_id,
                key,
                &format!("Merger for #{issue_id} exceeded its timeout without exiting"),
            );
        }
        handle.close();

        // Verify DONE (S3): a missing/torn sentinel is a Merger failure → park.
        if let Err(source) = DoneSentinel::verify(prepared.path()) {
            self.remove_worker(&worker_uuid);
            let _ = self.manager.forget(&name);
            return self.park_for_human(
                issue_id,
                key,
                &format!("Merger for #{issue_id} left no valid DONE sentinel: {source}"),
            );
        }
        self.remove_worker(&worker_uuid);

        // (4) The Merger's resolved working-copy commit. If it STILL carries a
        // conflict, the Merger did not resolve it → park (never land a conflict).
        //
        // Force a working-copy snapshot of the merger workspace FIRST (F5): a
        // Merger that resolved purely via `Edit`/`Write` and never ran a
        // snapshotting `jj` verb would leave its recorded commit stale, so the
        // readback below would still see the pre-resolution conflict and falsely
        // park a correct merge. The orchestrator owns the `.jj/` gate, so it folds
        // the on-disk edits in itself rather than trusting the worker's command
        // choices. Best-effort: a snapshot failure degrades to the prior
        // trust-the-worker readback (never worse than before F5), so it must not
        // fail the tick.
        let _ = self.manager.snapshot_workspace(&name);
        let merged = self.change_revset(&name, issue_id)?;
        let still_conflicted = self
            .manager
            .resolve_change(&merged)
            .map_err(PumpError::Landing)?
            .has_conflict;
        if still_conflicted {
            let _ = self.manager.forget(&name);
            return self.park_for_human(
                issue_id,
                key,
                &format!("Merger for #{issue_id} left the tree conflicted — unresolved merge"),
            );
        }

        // (5) Re-run static QA on the merged tree (REQ-19, AC-21). A fail/poison
        // is a Merger failure — no retry, park.
        let qa = self.qa_gate(prepared.path())?;
        match qa.run() {
            Ok(QaOutcome::Pass) => {
                emit(
                    &self.state,
                    &self.log,
                    EventKind::QaResult,
                    Some(key),
                    None,
                    &json!({"result": "pass", "phase": "post_merge"}),
                )?;
            }
            Ok(QaOutcome::Fail { exit_code, .. }) => {
                let _ = self.manager.forget(&name);
                return self.park_for_human(
                    issue_id,
                    key,
                    &format!("post-merge QA for #{issue_id} failed (exit {exit_code})"),
                );
            }
            Err(source) => {
                let _ = self.manager.forget(&name);
                return self.park_for_human(
                    issue_id,
                    key,
                    &format!("post-merge QA for #{issue_id} is broken/poison: {source}"),
                );
            }
        }

        // (6) Retry the FF landing ONCE. A clean FF → merged; a non-fast-forward
        // → park. Move main BEFORE forgetting the workspace so the resolved
        // commit is bookmark-referenced (never abandoned on forget).
        let land = retry_land_after_merge(&self.state, &self.log, &self.manager, key, &merged)?;
        let result = match land {
            LandingOutcome::Merged => {
                self.set_phase_label(issue_id, Phase::Merged)?;
                Ok(IssueOutcome::Merged)
            }
            LandingOutcome::AwaitingHumanMerge => {
                self.set_phase_label(issue_id, Phase::AwaitingHumanMerge)?;
                self.post_conflict_blocker(
                    issue_id,
                    &format!("retry landing for #{issue_id} was not a fast-forward after merge"),
                )?;
                Ok(IssueOutcome::AwaitingHumanMerge)
            }
            // A retry that re-conflicts is impossible here (the Merger produced a
            // conflict-free descendant of main); treat it as a park for safety.
            LandingOutcome::RebaseConflict { .. } => self.park_for_human(
                issue_id,
                key,
                &format!("retry landing for #{issue_id} unexpectedly re-conflicted"),
            ),
            // `retry_land_after_merge` drives only the local FF bookmark move
            // (REQ-19); it can never push a branch or open a PR. An impossible
            // `PrOpen` here is a safety park, not a merged/pr-open transition.
            LandingOutcome::PrOpen { .. } => self.park_for_human(
                issue_id,
                key,
                &format!("retry landing for #{issue_id} unexpectedly opened a PR"),
            ),
        };
        let _ = self.manager.forget(&name);
        result
    }

    /// Build the Merger worker command for `issue_id`, dispatched into the
    /// pre-rendered `rendered` workspace, per the typed `[worker] merger_kind`.
    ///
    /// Mirrors [`worker_command`](Self::worker_command) /
    /// [`adversary_worker_command`](Self::adversary_worker_command): a
    /// [`WorkerKind::Direct`] Merger runs the configured `merger_argv` straight in
    /// the conflicted workspace (the deterministic `fake-merger*` dogfood path —
    /// it resolves the conflicted files and writes `merge_result.md` + DONE),
    /// while a [`WorkerKind::Claude`] Merger is built from
    /// [`crate::roles::merger`] (its conflict-resolution allowlist, the
    /// `.jj/`+`.git/` RW mount matrix, system prompt, and `max_turns_merger`).
    fn merger_worker_command(
        &self,
        issue_id: i64,
        rendered: &crate::roles::merger::RenderedMergerInputs,
        task: &str,
    ) -> Result<WorkerCommand, PumpError> {
        let _ = issue_id;
        match self.config.worker.merger_kind {
            WorkerKind::Direct => {
                let argv = self
                    .config
                    .merger_argv(self.manager.root())
                    .ok_or(PumpError::EmptyWorkerCommand)?;
                Ok(WorkerCommand::direct(argv, Vec::<(String, String)>::new()))
            }
            WorkerKind::Claude => Ok(crate::roles::merger::worker_command(
                self.manager.root(),
                rendered,
                task.to_owned(),
                self.config.worker.max_turns_merger,
            )),
        }
    }

    /// Park an issue at `phase:awaiting-human-merge` (REQ-15a) after a Merger
    /// failure: set the authoritative phase, mirror the label, emit the
    /// transition, and post a `--kind blocker` with the conflict context (AC-14).
    /// A human applying `human-resolved:retry` re-attempts the landing.
    fn park_for_human(
        &self,
        issue_id: i64,
        key: &str,
        reason: &str,
    ) -> Result<IssueOutcome, PumpError> {
        self.state.set_phase(key, Phase::AwaitingHumanMerge, None)?;
        self.set_phase_label(issue_id, Phase::AwaitingHumanMerge)?;
        emit(
            &self.state,
            &self.log,
            EventKind::Transition,
            Some(key),
            None,
            &json!({
                "from_phase": Phase::Landing.as_str(),
                "to_phase": Phase::AwaitingHumanMerge.as_str(),
                "reason": reason,
            }),
        )?;
        self.post_conflict_blocker(issue_id, reason)?;
        Ok(IssueOutcome::AwaitingHumanMerge)
    }

    /// Park a converged `xb:inbound` (untrusted-origin) issue at
    /// `phase:awaiting-inbound-approval` instead of landing it (REQ-SWARM-1).
    ///
    /// This is the single structural enforcement of the threat model's "untrusted
    /// origin ⇒ HARD NO-GO on auto-land": reached from [`land`](Self::land) BEFORE
    /// the `tracker_remote` mode-select, so it forecloses BOTH the local-FF and the
    /// remote-PR landing paths — neither can auto-land untrusted work.
    ///
    /// Ordering is crash-safety-critical: the reviewed `change` is persisted
    /// ([`StateDb::set_landing_change`]) **before** the phase is flipped to
    /// `AwaitingInboundApproval`, so the instant the issue is observably parked the
    /// approval sweep can land *exactly* the reviewed change — the Implementer
    /// workspace is already forgotten by landing time, so the change cannot be
    /// re-derived from a workspace, and the store must outlive a restart-while-parked.
    ///
    /// A `--kind blocker` records, for a human, the exact label
    /// ([`INBOUND_APPROVED_LABEL`]) that authorizes landing. The park is a terminal
    /// phase, so the pump's answer-back trigger then answers the source peer once
    /// (spec §1.3) — the peer learns the work is pending approval and is never left
    /// waiting; the later merge does NOT answer a second time (the answer machine's
    /// first-terminal-wins guard).
    fn park_for_inbound_approval(
        &self,
        issue_id: i64,
        key: &str,
        change: &str,
    ) -> Result<IssueOutcome, PumpError> {
        // Persist the reviewed change FIRST (before the phase flip) — see the doc.
        self.state.set_landing_change(key, change)?;
        self.state
            .set_phase(key, Phase::AwaitingInboundApproval, None)?;
        self.set_phase_label(issue_id, Phase::AwaitingInboundApproval)?;
        emit(
            &self.state,
            &self.log,
            EventKind::Transition,
            Some(key),
            None,
            &json!({
                "from_phase": Phase::Converged.as_str(),
                "to_phase": Phase::AwaitingInboundApproval.as_str(),
                "reason": "xb:inbound (untrusted origin) — parked for human approval; never auto-lands",
                "gate": "REQ-SWARM-1",
            }),
        )?;
        let body = format!(
            "Parked at `phase:awaiting-inbound-approval`: this is an `xb:inbound` issue \
             (untrusted-origin work submitted by a peer over crossbridge). It has passed \
             implement → QA → adversary review and converged, but untrusted work **never \
             auto-lands** (regardless of local-FF or remote-PR mode).\n\n\
             A human must review the converged change and then apply the `{INBOUND_APPROVED_LABEL}` \
             label to authorize landing (REQ-SWARM-1). Until then it stays parked."
        );
        self.crosslink
            .comment_write(issue_id, "blocker", &body, Some(INBOUND_ROLE_TAG))?;
        Ok(IssueOutcome::AwaitingInboundApproval)
    }

    /// Post a `--kind blocker` recording the conflict context on an issue parked
    /// for a human merge (AC-14). Attributed to the Merger role (AC-16).
    fn post_conflict_blocker(&self, issue_id: i64, reason: &str) -> Result<(), PumpError> {
        let body = format!(
            "Landing parked at `phase:awaiting-human-merge`: {reason}.\n\n\
             A human must resolve the merge, then apply the `human-resolved:retry` \
             label to re-attempt the landing (REQ-15a)."
        );
        self.crosslink
            .comment_write(issue_id, "blocker", &body, Some(MERGER_ROLE_TAG))?;
        Ok(())
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
            // The workspace was already forgotten above; poison without one.
            return self.poison(
                key,
                None,
                &format!("QA for #{issue_id} still failing after {MAX_QA_RETRIES} attempts"),
            );
        }
        // Bump the round and re-queue at implementing; a later tick re-drives.
        // Reset `empty_round_streak` (the schema's reset rule (b): QA fail in any
        // round) so a stale clean-round streak from a prior implementation can't
        // survive a QA-fail re-spawn into A3's convergence detector.
        if let Some(mut issue) = issue {
            issue.round = round + 1;
            issue.phase = Phase::Implementing;
            issue.phase_substate = None;
            issue.empty_round_streak = 0;
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

    /// Build the worker command for `issue_id`, dispatched into `workspace`,
    /// per the typed `[worker] kind` (S7).
    ///
    /// - [`WorkerKind::Direct`] — the AC-11a dogfood: resolve the configured
    ///   argv against the repository root (so a relative fixture path works from
    ///   any cwd) and hand it to `WorkerCommand::Direct`. Unchanged from before
    ///   S7, so the dogfood stays green.
    /// - [`WorkerKind::Claude`] — a real Implementer: read the issue's title +
    ///   description from crosslink as the task (REQ-8, **untrusted input** — see
    ///   [`crate::roles::implementer::task_from_issue`]), append any accumulated
    ///   Adversary `prior_findings` so a re-implement round addresses them (REQ-8
    ///   fresh context — the findings reach the worker as task input, never as
    ///   session memory), and build the Implementer `WorkerCommand::Claude` from
    ///   [`crate::roles::implementer`]. The `Spawner` then enforces the mount
    ///   matrix, writes `task.md`, and verifies the `bwrap` pin.
    ///
    /// `prior_findings` is threaded into the Claude Implementer's `task.md` here;
    /// on the Direct path it is not folded into argv, because the pump already
    /// delivered it to the worker's workspace as `_orchestrator/prior_findings.jsonl`
    /// before the spawn ([`crate::roles::implementer::render_prior_findings`]) —
    /// the channel a Direct/generalized worker reads. So both paths receive the
    /// findings; only the delivery surface differs.
    fn worker_command(
        &self,
        issue_id: i64,
        workspace: &std::path::Path,
        prior_findings: &[Finding],
    ) -> Result<WorkerCommand, PumpError> {
        match self.config.worker.kind {
            WorkerKind::Direct => {
                let argv = self
                    .config
                    .worker_argv(self.manager.root())
                    .ok_or(PumpError::EmptyWorkerCommand)?;
                Ok(WorkerCommand::direct(argv, Vec::<(String, String)>::new()))
            }
            WorkerKind::Claude => {
                let info = self.crosslink.read_issue(issue_id)?;
                let task = crate::roles::implementer::task_from_issue(
                    &info.title,
                    info.description.as_deref(),
                );
                let task = append_prior_findings(task, prior_findings);
                Ok(crate::roles::implementer::worker_command(
                    self.manager.root(),
                    workspace,
                    task,
                    self.config.worker.max_turns_implementer,
                ))
            }
        }
    }

    /// Build the Adversary worker command for `issue_id`, dispatched into the
    /// pre-rendered `rendered` workspace, per the typed `[worker] adversary_kind`.
    ///
    /// Mirrors [`worker_command`](Self::worker_command): a
    /// [`WorkerKind::Direct`] Adversary runs the configured `adversary_argv`
    /// straight in the pre-rendered workspace (the deterministic `fake-adversary*`
    /// dogfood path — it reads `_orchestrator/diff.patch` and writes
    /// `findings.jsonl`), while a [`WorkerKind::Claude`] Adversary is built from
    /// [`crate::roles::adversary`] (its narrow allowlist, no-`.jj/` mount matrix,
    /// system prompt, and `max_turns_adversary`). The Adversary's inputs were
    /// already rendered by [`render_inputs`], proven by the
    /// [`RenderedAdversaryInputs`] token this takes.
    fn adversary_worker_command(
        &self,
        issue_id: i64,
        rendered: &RenderedAdversaryInputs,
        task: &str,
    ) -> Result<WorkerCommand, PumpError> {
        let _ = issue_id;
        match self.config.worker.adversary_kind {
            WorkerKind::Direct => {
                let argv = self
                    .config
                    .adversary_argv(self.manager.root())
                    .ok_or(PumpError::EmptyWorkerCommand)?;
                Ok(WorkerCommand::direct(argv, Vec::<(String, String)>::new()))
            }
            WorkerKind::Claude => Ok(crate::roles::adversary::worker_command(
                self.manager.root(),
                rendered,
                task.to_owned(),
                self.config.worker.max_turns_adversary,
            )),
        }
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
        role: WorkerRole,
        round: u32,
        workspace_path: &std::path::Path,
    ) -> Result<(), PumpError> {
        let now = now_unix();
        self.state.upsert_worker(&ActiveWorkerRow {
            worker_uuid: worker_uuid.to_owned(),
            issue_id: key.to_owned(),
            role,
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

    /// Re-hydrate the prior Adversary findings for an issue from the durable
    /// `--kind blocker` comments they were posted as (#2, REQ-8).
    ///
    /// The in-memory `prior_findings` accumulator that threads findings from one
    /// re-implement round to the next is lost on a crash: recovery rolls the
    /// issue back to `implementing`, and the next `drive_issue` starts with an
    /// empty accumulator, so the re-implement would be BLIND while the persisted
    /// `round` climbs toward the poison cap. The findings ARE durable, though —
    /// each was posted as an idempotent `--kind blocker` with the `[adversary]`
    /// role marker. Reading them back seeds the next Implementer's task (not
    /// blind) AND the next Adversary's `prior_findings.json`.
    ///
    /// Only Adversary blockers are re-hydrated: they carry the `[adversary]`
    /// marker line, distinguishing them from QA-failure blockers (posted with
    /// the `[implementer]` marker), which are not findings and whose bodies
    /// don't parse as one anyway. On a first (non-crash) entry there are no
    /// blockers yet, so this returns `[]`.
    fn rehydrate_prior_findings(&self, issue_id: i64) -> Result<Vec<Finding>, PumpError> {
        let marker = format!("[{ADVERSARY_ROLE_TAG}]\n\n");
        let mut out = Vec::new();
        for comment in self.crosslink.list_comments(issue_id)? {
            if comment.kind != CommentKind::Blocker.as_str() {
                continue;
            }
            let Some(body) = comment.body.strip_prefix(&marker) else {
                continue;
            };
            if let Some(finding) = parse_finding_from_body(body) {
                out.push(finding);
            }
        }
        Ok(out)
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
    ///
    /// `workspace` is the workspace to clean up, or `None` when the caller has
    /// already forgotten every workspace it owned (the adversary-review paths,
    /// where the Implementer workspace was forgotten before the review and each
    /// round's Adversary workspace is forgotten as the round ends) — so the
    /// cleanup is correct by construction, never a fabricated name that only
    /// no-ops by accident.
    fn poison(
        &self,
        key: &str,
        workspace: Option<&WorkspaceName>,
        reason: &str,
    ) -> Result<IssueOutcome, PumpError> {
        // Best-effort workspace cleanup — a poison must not leak the workspace.
        if let Some(name) = workspace {
            let _ = self.manager.forget(name);
        }
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
    /// idempotently against the `posted_artifacts` ledger (REQ-3, REQ-3b,
    /// AC-17).
    ///
    /// Each planned comment is posted at most once: the content-addressed
    /// `(issue_id, artifact_path, content_sha, finding_index)` tuple is checked
    /// against the ledger first; a tuple already recorded is skipped. Keying on
    /// the issue + content (not the worker uuid) means a re-translation of
    /// identical content under a fresh uuid — a crash-recovery re-drive — is also
    /// suppressed, so a comment posts at most once across attempts.
    ///
    /// `role_tag` is the AC-16 attribution recorded on the posted comments —
    /// [`WORKER_ROLE_TAG`] for the Implementer's `result.md`, [`ADVERSARY_ROLE_TAG`]
    /// for the Adversary's findings (`--kind blocker`) + review summary.
    fn translate_artifacts(
        &self,
        issue_id: i64,
        worker_uuid: &str,
        role_tag: &str,
        done: &DoneSentinel,
    ) -> Result<(), PumpError> {
        let issue_key = issue_id.to_string();
        let set = ArtifactSet { done: done.clone() };
        let plan = crate::artifacts::translation_plan(worker_uuid, &set)?;
        for item in plan {
            if self.state.is_posted(
                &issue_key,
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
                Some(role_tag),
            )?;
            self.state.record_posted(&crate::state::PostedArtifact {
                issue_id: issue_key.clone(),
                artifact_path: item.artifact_path,
                content_sha: item.content_sha,
                finding_index: item.finding_index,
                worker_uuid: worker_uuid.to_owned(),
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

/// Reconstruct a [`Finding`] from the body of the `--kind blocker` comment it
/// was posted as — the inverse of [`Finding::comment_body`], for re-hydrating
/// prior findings from crosslink after a crash (#2, REQ-8).
///
/// The body shape is deterministic (produced by `comment_body`):
///
/// ```text
/// [<severity>] <claim>
/// location: <path>:<line>
/// [evidence:
/// - <file>
/// - <file>]
/// ```
///
/// A body that doesn't match (e.g. a QA-failure blocker, whose text is not a
/// finding) yields `None` and is skipped — so only genuine Adversary findings
/// re-hydrate. The reconstruction is close enough for both consumers: the
/// Implementer's task text (the REQ-8 essence — the finding reaches the next
/// round as input) and the Adversary's `prior_findings.json`.
fn parse_finding_from_body(text: &str) -> Option<Finding> {
    let mut lines = text.lines();
    let head = lines.next()?;
    let (sev_tok, claim) = head.strip_prefix('[')?.split_once("] ")?;
    let severity = match sev_tok {
        "high" => Severity::High,
        "med" => Severity::Med,
        "low" => Severity::Low,
        _ => return None,
    };
    let mut location = None;
    let mut evidence_files = Vec::new();
    let mut in_evidence = false;
    for line in lines {
        if let Some(loc) = line.strip_prefix("location: ") {
            location = Location::parse(loc);
        } else if line == "evidence:" {
            in_evidence = true;
        } else if in_evidence {
            if let Some(file) = line.strip_prefix("- ") {
                evidence_files.push(file.to_owned());
            }
        }
    }
    Some(Finding {
        severity,
        location: location?,
        claim: claim.to_owned(),
        evidence_files,
    })
}

/// Whether a crosslink label set contains `label` exactly — the presence check
/// the inbound approval gate (REQ-SWARM-1) uses for [`INBOUND_APPROVED_LABEL`].
fn has_label(labels: &[String], label: &str) -> bool {
    labels.iter().any(|l| l == label)
}

/// Append the accumulated Adversary `prior_findings` to a fresh Implementer's
/// task (REQ-8): the findings reach the worker as task input, so a re-implement
/// round addresses them, never as agent session memory. Empty findings leave the
/// task untouched.
fn append_prior_findings(task: String, prior_findings: &[Finding]) -> String {
    if prior_findings.is_empty() {
        return task;
    }
    let mut out = task;
    out.push_str("\n\n## Prior adversary findings to address\n");
    for finding in prior_findings {
        out.push_str(&format!(
            "\n- {}",
            finding.comment_body().replace('\n', "\n  ")
        ));
    }
    out
}

/// One step of the Implementer round ([`BuildPump::run_implementer_round`]).
enum ImplStep {
    /// A terminal-or-requeued outcome was reached before review (poison, empty
    /// change, QA fail → requeue, QA poison) — return it directly.
    Done(IssueOutcome),
    /// QA passed: the workspace name of the Implementer's change, from which the
    /// adversary review resolves the change revset before forgetting the
    /// workspace DIR (#1). The prepared workspace itself is not carried — it
    /// holds no `Drop`, and the committed change is durable in `.jj/`.
    QaPassed {
        /// The Implementer workspace name — the change-revset handle.
        name: WorkspaceName,
    },
}

/// One step of the Adversary review ([`BuildPump::run_adversary_review`]).
enum ReviewStep {
    /// A terminal outcome was reached — converged → landed, an incomplete
    /// Adversary poisoned, or the round cap tripped.
    Done(IssueOutcome),
    /// The Adversary reported findings: they were posted as blockers, the round
    /// bumped, and the phase rolled back to `Implementing`. The caller loops to
    /// re-spawn a fresh Implementer.
    Reimplement,
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
        assert!(
            IssueOutcome::AwaitingInboundApproval.is_terminal(),
            "an inbound issue parked for approval is a terminal (parked) outcome"
        );
        assert!(IssueOutcome::OrchestratorError.is_terminal());
        assert!(
            !IssueOutcome::Requeued.is_terminal(),
            "requeue is re-driven"
        );
    }

    #[test]
    fn has_label_is_exact_match() {
        let labels = vec![
            "xb:inbound".to_owned(),
            "inbound-approved:land".to_owned(),
            "phase:converged".to_owned(),
        ];
        assert!(has_label(&labels, INBOUND_APPROVED_LABEL));
        assert!(has_label(&labels, "xb:inbound"));
        // Not a prefix / substring match — the exact label must be present.
        assert!(!has_label(&labels, "inbound-approved"));
        assert!(!has_label(&labels, "phase:merged"));
        assert!(!has_label(&[], INBOUND_APPROVED_LABEL));
    }

    #[test]
    fn state_db_path_is_under_orchestrator_dir() {
        let p = state_db_path(std::path::Path::new("/repo"));
        assert!(p.ends_with(".orchestrator/state.db"));
    }

    /// #2: a blocker body reconstructs exactly back into its `Finding` (the
    /// inverse of `Finding::comment_body`), so a crash-re-hydrated finding is
    /// faithful — and it reaches the next Implementer as task input (the REQ-8
    /// essence: the re-implement is NOT blind).
    #[test]
    fn blocker_body_round_trips_into_finding_and_reaches_implementer() {
        let finding = Finding {
            severity: Severity::High,
            location: Location::parse("src/lib.rs:12").expect("location"),
            claim: "say_hi has no boundary test".to_owned(),
            evidence_files: vec!["src/lib.rs".to_owned(), "src/main.rs".to_owned()],
        };
        // comment_body → parse_finding_from_body is a faithful round-trip.
        let body = finding.comment_body();
        let parsed = parse_finding_from_body(&body).expect("body must reconstruct a finding");
        assert_eq!(parsed, finding);

        // A finding with no evidence still round-trips.
        let no_evidence = Finding {
            evidence_files: Vec::new(),
            ..finding.clone()
        };
        assert_eq!(
            parse_finding_from_body(&no_evidence.comment_body()).expect("parse"),
            no_evidence
        );

        // The reconstructed finding reaches the Implementer as task text — this
        // is exactly what `worker_command` (Claude path) feeds a re-implement
        // round, so the re-entry is not blind.
        let task = append_prior_findings("Implement say_hi".to_owned(), &[parsed]);
        assert!(task.contains("Prior adversary findings"));
        assert!(task.contains("say_hi has no boundary test"));
    }

    /// A QA-failure blocker (not a finding) must NOT reconstruct as a finding —
    /// so re-hydration ignores it (only `[adversary]` findings are seeded).
    #[test]
    fn qa_failure_blocker_body_is_not_parsed_as_a_finding() {
        let qa_body = "Static QA failed (exit 1). Last output:\n\n```\nerror[E0308]\n```";
        assert!(parse_finding_from_body(qa_body).is_none());
    }
}
