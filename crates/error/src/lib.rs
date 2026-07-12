//! Common diagnostic error types for the vetinari orchestrator (REQ-1b).
//!
//! Every public error type implements [`miette::Diagnostic`] so it renders as
//! a compiler-style report when written to `events.jsonl` or printed to the
//! terminal. Variants are organized by phase so call sites construct concrete
//! errors and the orchestrator's top-level loop matches on them without
//! string-comparing messages.
//!
//! Construct errors directly via their variants — no helper factories — and
//! convert to the top-level [`OrchestratorError`] with `?` thanks to the
//! `#[from]` derivations on each variant.

#![deny(missing_docs)]
#![forbid(unsafe_code)]
// Each variant deliberately carries rich diagnostic context (NamedSource for
// `miette` span rendering, captured stderr tails, conflict-file lists). Errors
// propagate at human decision rate, not inside hot loops, so the ~136-byte
// variant size is fine and is the wrong axis to optimize.
#![allow(clippy::result_large_err)]

use std::path::PathBuf;
use std::time::Duration;

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

// ============================================================================
// Top-level error
// ============================================================================

/// Catch-all orchestrator error. Library code returns one of the concrete
/// variants below; the binary entrypoint matches on this at the top of `main`
/// to decide whether the failure is fatal or per-issue.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum OrchestratorError {
    /// Failure during a worker spawn — see [`SpawnError`].
    #[error(transparent)]
    #[diagnostic(transparent)]
    Spawn(#[from] SpawnError),

    /// Failure inside the static QA gate — see [`QaError`].
    #[error(transparent)]
    #[diagnostic(transparent)]
    Qa(#[from] QaError),

    /// Failure during the landing (rebase / push / PR-create) step — see
    /// [`LandingError`].
    #[error(transparent)]
    #[diagnostic(transparent)]
    Landing(#[from] LandingError),

    /// Failure during crash-safe resumption — see [`RecoveryError`].
    #[error(transparent)]
    #[diagnostic(transparent)]
    Recovery(#[from] RecoveryError),

    /// Failure parsing or translating worker output — see [`ArtifactError`].
    #[error(transparent)]
    #[diagnostic(transparent)]
    Artifact(#[from] ArtifactError),

    /// Failure in the SQLite-backed `state.db` layer — see [`StateError`].
    #[error(transparent)]
    #[diagnostic(transparent)]
    State(#[from] StateError),
}

/// Convenience `Result` alias.
pub type Result<T, E = OrchestratorError> = std::result::Result<T, E>;

// ============================================================================
// Spawn errors (REQ-4, REQ-4a, REQ-5, REQ-1d)
// ============================================================================

/// Errors raised while preparing or launching a worker.
///
/// Spawn failures are routed to `phase:orchestrator-error` and require human
/// intervention — they indicate the host environment is wrong, not that a
/// particular issue is hard.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum SpawnError {
    /// The pinned `claude-sandbox` binary doesn't match what's on `PATH`.
    /// Refuses to spawn rather than risk a posture regression.
    #[error("claude-sandbox version mismatch: expected `{expected}`, found `{found}`")]
    #[diagnostic(
        code(vetinari::spawn::claude_sandbox_version_mismatch),
        help("Re-enter the dev shell with `nix develop`. If the flake's pin needs bumping, see REQ-4a in .design/vdd-orchestrator.md."),
        url("https://github.com/vringar/vetinari/blob/main/.design/vdd-orchestrator.md#req-4a")
    )]
    ClaudeSandboxVersionMismatch {
        /// Nix store path or version string the flake baked in at build time.
        expected: String,
        /// Nix store path or version string discovered at runtime.
        found: String,
    },

    /// `claude-sandbox` could not be located on the current `PATH`.
    #[error("claude-sandbox binary not found (searched: {searched})")]
    #[diagnostic(
        code(vetinari::spawn::claude_sandbox_missing),
        help("Enter the dev shell (`nix develop`) or install claude-sandbox into the active profile.")
    )]
    ClaudeSandboxMissing {
        /// `PATH` value (or other search list) that turned up no binary.
        searched: String,
    },

    /// The headless zellij session this orchestrator hosts workers in could
    /// not be created or attached to.
    #[error("zellij session `{session_name}` is unavailable")]
    #[diagnostic(
        code(vetinari::spawn::zellij_session_unavailable),
        help(
            "Check that the zellij socket isn't owned by another user; try `zellij list-sessions`."
        ),
        url("https://github.com/vringar/vetinari/blob/main/.design/vdd-orchestrator.md#req-1d")
    )]
    ZellijSessionUnavailable {
        /// Session name the orchestrator tried (default: `vdd-orchestrator`).
        session_name: String,
        /// Underlying cause if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// Creating a fresh zellij pane for a new worker failed.
    #[error("zellij pane create failed for `{pane_name}`")]
    #[diagnostic(
        code(vetinari::spawn::zellij_pane_create_failed),
        help("The session is up but the IPC RPC rejected the create request — see source for details.")
    )]
    ZellijPaneCreateFailed {
        /// Intended pane name (e.g. `implementer-42-r3`).
        pane_name: String,
        /// Underlying cause.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// A workspace path already exists when the spawn helper expected to own
    /// it. Indicates a previous run died without `jj workspace forget`.
    /// REQ-12 says cleanup-before-spawn handles this, but if cleanup itself
    /// fails we surface the path so a human can inspect.
    #[error("workspace path `{path}` is occupied and could not be cleaned")]
    #[diagnostic(
        code(vetinari::spawn::workspace_path_conflict),
        help("Inspect the path manually; `jj workspace forget` if you trust the deletion.")
    )]
    WorkspacePathConflict {
        /// Path that conflicted.
        path: PathBuf,
    },

    /// `bwrap` (or its wrapper) exited non-zero before launching `claude`.
    #[error("bwrap failed (exit {exit_code}): {stderr_tail}")]
    #[diagnostic(
        code(vetinari::spawn::bwrap_failed),
        help("Check mount paths and capabilities; bwrap stderr is preserved verbatim above.")
    )]
    BwrapFailed {
        /// Exit code from the bwrap process.
        exit_code: i32,
        /// Last ~50 lines of stderr — kept truncated for events.jsonl sanity.
        stderr_tail: String,
    },

    /// The Claude Code PostToolUse hook required for heartbeats is missing
    /// from the worker's `.claude/hooks/` view.
    #[error("required hook `{hook}` is missing from the worker's hook configuration")]
    #[diagnostic(
        code(vetinari::spawn::hook_config_missing),
        help("The flake should symlink crosslink's heartbeat.py into .claude/hooks/. See REQ-11.")
    )]
    HookConfigMissing {
        /// Hook name (e.g. `heartbeat.py`).
        hook: String,
    },

    /// Filesystem I/O failure during workspace preparation.
    #[error("io error at `{path}`: {source}")]
    #[diagnostic(code(vetinari::spawn::io))]
    Io {
        /// Path whose access failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A `jj_api` workspace-lifecycle operation (add / forget / list) failed
    /// while the spawn helper was preparing a worker's workspace (REQ-12). The
    /// underlying `jj-lib` cause is wrapped by `jj_api`; this adds the
    /// workspace path for context.
    #[error("jj workspace preparation failed for `{path}`")]
    #[diagnostic(
        code(vetinari::spawn::workspace_prep),
        help("Inspect `jj op log` and the workspace path; a prior crash may have left the repository view inconsistent.")
    )]
    WorkspacePrep {
        /// Workspace directory being prepared.
        path: PathBuf,
        /// Underlying `jj_api` cause.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

// ============================================================================
// QA gate errors (REQ-9, AC-7)
// ============================================================================

/// Errors raised by the static QA gate.
///
/// Every variant here is **poison**: it means the gate itself is broken, hung,
/// or died — not that a QA tool returned non-zero. A real QA-tool failure is a
/// deterministic *verdict*, carried by `QaOutcome::Fail`, never a `QaError`.
/// These variants all route the issue to `phase:orchestrator-error` for human
/// inspection, never a `--kind blocker` (see the design's error-handling
/// section: "`static_qa.sh` itself errors" is distinct from "a QA tool returned
/// non-zero").
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum QaError {
    /// `.orchestrator/static_qa.sh` does not exist.
    #[error("static QA script `{path}` not found")]
    #[diagnostic(
        code(vetinari::qa::script_not_found),
        help("Initialize the QA script per design.md REQ-9 — copy the template from the docs.")
    )]
    ScriptNotFound {
        /// Expected path.
        path: PathBuf,
    },

    /// The `bash <script>` child could not even be spawned — `bash` itself is
    /// missing from PATH, or the path could not be reached (an unsearchable
    /// parent directory). The script's own `+x` bit is irrelevant: the gate runs
    /// it as `bash <path>`, so the shebang and the executable bit are ignored
    /// (only `bash` needs to be executable). Like [`ScriptNotFound`], this is
    /// repo/host misconfiguration, not a failed check, so it routes to
    /// `phase:orchestrator-error`, never a blocker.
    ///
    /// [`ScriptNotFound`]: QaError::ScriptNotFound
    #[error("static QA script `{path}` could not be spawned")]
    #[diagnostic(
        code(vetinari::qa::script_unspawnable),
        help("Check that `bash` is on PATH and the script's parent directory is reachable. The script need not be executable — it is run as `bash <path>`.")
    )]
    ScriptUnspawnable {
        /// Path the orchestrator tried to run.
        path: PathBuf,
        /// Underlying spawn (I/O) error.
        #[source]
        source: std::io::Error,
    },

    /// The gate is structurally broken: `bash` could not execute the script
    /// (exit 126 — not executable / not a valid program), or a command *inside*
    /// the script was not found (exit 127 — e.g. `cargo` missing from PATH).
    /// Either way the gate never ran the QA tools, so this is repo/host
    /// misconfiguration rather than a real failed check.
    #[error("static QA script errored before running any tool (exit {exit_code})")]
    #[diagnostic(
        code(vetinari::qa::script_errored),
        help("Run the script directly and read the shell error; the orchestrator cannot proceed until it's well-formed. Exit 126 means not executable / cannot exec; 127 means a command inside the script (e.g. `cargo`) is missing from PATH.")
    )]
    ScriptItselfErrored {
        /// Script exit code (126 = cannot exec, 127 = command-not-found).
        exit_code: i32,
        /// Last ~50 lines of the script's combined output, for the human who
        /// inspects the poison state.
        message: String,
    },

    /// The QA script was killed by a signal (exit code is `None`): an OOM kill,
    /// a `SIGKILL`, or similar. That is an environmental anomaly, not a QA tool
    /// saying no, so it is poison — the orchestrator surfaces it rather than
    /// treating it as a routine blocker.
    #[error("static QA script was killed by a signal{}", match signal { Some(s) => format!(" ({s})"), None => String::new() })]
    #[diagnostic(
        code(vetinari::qa::script_killed),
        help("The script died before exiting normally — check for OOM (dmesg), a `kill`, or a resource limit. This is an environment anomaly, not a failed check.")
    )]
    Killed {
        /// The terminating signal number, if the platform exposed it.
        signal: Option<i32>,
        /// Last ~50 lines of output captured before the kill, for inspection.
        message: String,
    },

    /// The QA script did not finish within the gate's timeout. A wedged script
    /// (a hung `cargo`, a deadlocked test) must not brick the headless pump —
    /// no heartbeat watchdog covers the orchestrator-run gate — so the gate
    /// kills the child and surfaces this as poison for human inspection.
    #[error("static QA script timed out after {after:.1?}")]
    #[diagnostic(
        code(vetinari::qa::timed_out),
        help("The script exceeded DEFAULT_QA_TIMEOUT. A hang is an anomaly the orchestrator must surface, not silently retry — inspect why the gate wedged (deadlocked test, network wait).")
    )]
    TimedOut {
        /// How long the gate waited before killing the child.
        after: Duration,
    },
}

// ============================================================================
// Landing errors (REQ-17, REQ-19, REQ-15a, REQ-2a)
// ============================================================================

/// Errors during the rebase / fast-forward / push / PR-create dance.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum LandingError {
    /// `jj rebase` produced a conflict. Triggers Merger spawn (REQ-19).
    #[error("jj rebase conflict on {} file(s)", conflicted_files.len())]
    #[diagnostic(
        code(vetinari::landing::rebase_conflict),
        help("Spawning a Merger; see _orchestrator/conflict.md once the pane is up."),
        url("https://github.com/vringar/vetinari/blob/main/.design/vdd-orchestrator.md#req-19")
    )]
    RebaseConflict {
        /// Files left with conflict markers after jj's attempted rebase.
        conflicted_files: Vec<PathBuf>,
    },

    /// `jj git push` rejected by the remote because of divergence. Triggers
    /// Merger spawn (REQ-19 remote path).
    #[error("push to `{remote}` rejected (remote diverged on {remote_ref})")]
    #[diagnostic(
        code(vetinari::landing::push_conflict),
        help("Spawning a Merger to fetch + rebase before retry.")
    )]
    PushConflict {
        /// Remote name (typically `origin`).
        remote: String,
        /// Ref the push targeted.
        remote_ref: String,
    },

    /// The bookmark fast-forward step itself failed after a clean rebase.
    /// Distinct because the rebase succeeded; no Merger is needed.
    #[error("bookmark `{bookmark}` could not be moved")]
    #[diagnostic(
        code(vetinari::landing::bookmark_move_failed),
        help("Check `jj op log` for the failed operation. May indicate stale bookmark state.")
    )]
    BookmarkMoveFailed {
        /// Bookmark name (e.g. `vdd/42-add-batch-retry`).
        bookmark: String,
        /// Underlying error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// `gh` is not authenticated and remote-mode landing was attempted.
    #[error("gh authentication missing (remote mode requires GH_TOKEN or an authenticated `gh auth status`)")]
    #[diagnostic(
        code(vetinari::landing::gh_auth_missing),
        help("Run `gh auth login` on the host, or set GH_TOKEN in the env. See AC-12.")
    )]
    GhAuthMissing,

    /// `gh pr create` returned non-zero.
    #[error("gh pr create failed (exit {exit_code})")]
    #[diagnostic(
        code(vetinari::landing::pr_create_failed),
        help("Check the body for unsupported markdown or branch state issues.")
    )]
    PrCreateFailed {
        /// `gh` exit code.
        exit_code: i32,
        /// `gh` stderr tail.
        stderr_tail: String,
    },

    /// The Merger produced a workspace state that still has conflict markers
    /// or otherwise failed the schema check (no DONE sentinel, malformed
    /// merge_result.md, etc.). Treated per REQ-19 as Merger-failure and
    /// routes to `phase:awaiting-human-merge`.
    #[error("Merger produced an invalid result: {reason}")]
    #[diagnostic(
        code(vetinari::landing::merger_invalid_result),
        help("A human needs to inspect; the issue will sit at phase:awaiting-human-merge.")
    )]
    MergerProducedInvalidResult {
        /// One-line summary of what went wrong.
        reason: String,
    },

    /// Post-Merger static QA failed. Per REQ-19 this is treated as Merger
    /// failure: no retry, transition to `phase:awaiting-human-merge`.
    #[error("post-merge QA gate failed: {0}")]
    #[diagnostic(
        code(vetinari::landing::post_merge_qa_failed),
        help("The Merger produced a clean rebase but the result fails QA. A human merge is required."),
        url("https://github.com/vringar/vetinari/blob/main/.design/vdd-orchestrator.md#req-19")
    )]
    PostMergeQaFailed(
        #[source]
        #[diagnostic_source]
        QaError,
    ),

    /// Recovery found a landing substate that doesn't match filesystem ground
    /// truth (REQ-2a).
    #[error("landing substate `{substate}` disagrees with filesystem truth: {fs_truth}")]
    #[diagnostic(
        code(vetinari::landing::substate_inconsistent),
        help(
            "The recovery table couldn't reconcile; check `jj log` and `gh pr list` for the issue."
        )
    )]
    SubstateInconsistent {
        /// Substate recorded in state.db.
        substate: String,
        /// What the filesystem says.
        fs_truth: String,
    },
}

// ============================================================================
// Recovery errors (REQ-15, AC-17, AC-18)
// ============================================================================

/// Errors raised by the crash-safe resumption path. Recovery is meant to be
/// idempotent; an error here indicates we cannot derive a consistent state and
/// the orchestrator refuses to advance the affected issue.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum RecoveryError {
    /// The persisted `phase_substate` is unknown to this binary. Typically
    /// happens when a newer binary writes a substate and an older binary
    /// tries to recover.
    #[error("unknown phase substate `{substate}` (phase `{phase}`)")]
    #[diagnostic(
        code(vetinari::recovery::unknown_substate),
        help("Run the latest orchestrator binary against this state.db. Forward-only schema; never downgrade.")
    )]
    UnknownSubstate {
        /// Phase recorded.
        phase: String,
        /// Substate recorded.
        substate: String,
    },

    /// An active_workers row points at a workspace path that no longer
    /// exists. Routine cleanup case.
    #[error("active worker `{worker_uuid}` references missing workspace `{expected_path}`")]
    #[diagnostic(
        code(vetinari::recovery::workspace_missing),
        help(
            "The orchestrator will drop the row and transition the issue back to its prior phase."
        )
    )]
    WorkspaceMissingForActiveWorker {
        /// Worker UUID from active_workers.
        worker_uuid: String,
        /// Path the row claimed.
        expected_path: PathBuf,
    },

    /// The state.db itself is in an inconsistent shape — e.g. an issue is in
    /// `phase:landing` but has no `landing_retry_count`, or a worker row's
    /// `issue_id` doesn't map to any row in `issues`.
    #[error("state.db inconsistency: {detail}")]
    #[diagnostic(
        code(vetinari::recovery::state_db_inconsistent),
        help("Refuse to advance the affected issue; a human or `crosslink integrity` operation must reconcile.")
    )]
    StateDbInconsistent {
        /// One-line summary of the inconsistency.
        detail: String,
    },

    /// jj log shows revisions that disagree with the substate's claim.
    #[error("jj log mismatches substate `{substate}` (saw revs: {actual_revs:?})")]
    #[diagnostic(
        code(vetinari::recovery::jj_log_mismatch),
        help("Run `jj op log` to understand what produced the divergence; recovery refuses to advance until reconciled.")
    )]
    JjLogMismatchesSubstate {
        /// Substate name.
        substate: String,
        /// Revisions actually present.
        actual_revs: Vec<String>,
    },
}

// ============================================================================
// Artifact errors (REQ-3, REQ-3b, AC-23)
// ============================================================================

/// Errors raised while parsing or translating worker output artifacts.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum ArtifactError {
    /// The worker did not write the `_orchestrator/DONE` sentinel. Treated as
    /// a crash regardless of process exit code (REQ-3b).
    #[error("worker did not write DONE sentinel in `{workspace}` — treating as crash")]
    #[diagnostic(
        code(vetinari::artifact::done_missing),
        help("The orchestrator will clean the workspace and re-spawn from the prior phase.")
    )]
    DoneSentinelMissing {
        /// Workspace path whose worker is presumed crashed.
        workspace: PathBuf,
    },

    /// A worker artifact failed schema validation. The labeled span points at
    /// the offending line within the source file.
    #[error("schema violation in `{artifact}` line {line_no}")]
    #[diagnostic(
        code(vetinari::artifact::schema_violation),
        help("Worker produced malformed output. Re-spawning with the same input; if the next attempt also fails, treat as Implementer bug.")
    )]
    SchemaViolation {
        /// Artifact path.
        artifact: PathBuf,
        /// 1-based line number.
        line_no: usize,
        /// Source file content for miette rendering.
        #[source_code]
        src: NamedSource<String>,
        /// Span covering the offending line.
        #[label("malformed here")]
        offending: SourceSpan,
        /// Underlying parser error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// The `_orchestrator/DONE` sentinel exists but its JSON body is not
    /// well-formed against the REQ-3b schema (`{"exit_status": ..,
    /// "artifacts": [{"path": .., "sha256": ..}]}`). This is the AC-23
    /// torn-write class where DONE itself landed half-written; treat as crash.
    #[error("DONE sentinel at `{path}` is malformed: {reason}")]
    #[diagnostic(
        code(vetinari::artifact::done_malformed),
        help("DONE was written truncated or with the wrong shape. Re-spawn the worker from the prior phase.")
    )]
    DoneMalformed {
        /// Path to the `_orchestrator/DONE` file.
        path: PathBuf,
        /// One-line summary of what failed to parse.
        reason: String,
    },

    /// The DONE sentinel lists an artifact path that is not confined to the
    /// worker's workspace — absolute, or escaping via `..`. `verify` runs
    /// orchestrator-side (outside the sandbox), so joining such a path would let
    /// a garbled or malicious worker DONE point the orchestrator at an arbitrary
    /// host file (AC-23). Rejected before any read; treat as crash.
    #[error("DONE sentinel lists unsafe artifact path `{artifact}` (must be workspace-relative)")]
    #[diagnostic(
        code(vetinari::artifact::done_artifact_path_unsafe),
        help("A well-behaved worker writes artifacts under `_orchestrator/`. An absolute or `..`-escaping path means the DONE was garbled or hostile. Re-spawn.")
    )]
    DoneArtifactPathUnsafe {
        /// The offending path exactly as DONE spelled it.
        artifact: PathBuf,
    },

    /// The DONE sentinel lists an artifact path that does not exist on disk.
    /// A torn write where DONE was fsynced before its artifacts (AC-23);
    /// treat as crash.
    #[error("DONE sentinel lists artifact `{artifact}` that is missing on disk")]
    #[diagnostic(
        code(vetinari::artifact::done_artifact_missing),
        help(
            "The DONE sentinel references an artifact the worker never finished writing. Re-spawn."
        )
    )]
    DoneArtifactMissing {
        /// Artifact path DONE claimed.
        artifact: PathBuf,
        /// Underlying I/O error encountered when reading the artifact.
        #[source]
        source: std::io::Error,
    },

    /// The DONE sentinel's recorded checksum doesn't match what's on disk.
    /// Indicates a partial write where DONE landed before the artifact was
    /// fully fsynced — treat as crash.
    #[error("checksum mismatch for `{artifact}` (DONE said {expected}, computed {actual})")]
    #[diagnostic(
        code(vetinari::artifact::checksum_mismatch),
        help("The artifact was modified after DONE was written, or DONE was written before fsync. Re-spawn.")
    )]
    ChecksumMismatch {
        /// Artifact path.
        artifact: PathBuf,
        /// SHA-256 the DONE sentinel claimed.
        expected: String,
        /// SHA-256 the orchestrator computed.
        actual: String,
    },

    /// Could not read the artifact file at all.
    #[error("could not read artifact `{path}`: {source}")]
    #[diagnostic(code(vetinari::artifact::read_failed))]
    ReadFailed {
        /// Path attempted.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Idempotency guard tripped: this exact artifact-content + finding-index
    /// pair has already been posted as a crosslink comment. Not fatal; the
    /// caller skips the post and continues.
    #[error("artifact `{artifact}` finding index {finding_index} for worker `{worker_uuid}` already posted")]
    #[diagnostic(
        code(vetinari::artifact::duplicate_posting),
        severity(Warning),
        help("posted_artifacts table already contains this tuple; nothing to do.")
    )]
    DuplicatePosting {
        /// Worker UUID.
        worker_uuid: String,
        /// Artifact path.
        artifact: PathBuf,
        /// Index within a multi-finding artifact (e.g. findings.jsonl); use
        /// -1 for whole-file artifacts like result.md.
        finding_index: i32,
    },
}

// ============================================================================
// State persistence errors (REQ-2, REQ-2a, REQ-3b, AC-2)
// ============================================================================

/// Errors raised by the SQLite-backed `state.db` layer.
///
/// `state.db` is the orchestrator's authoritative state (REQ-2). A failure
/// here means the orchestrator can no longer trust its own bookkeeping, so it
/// stops the whole run rather than mis-routing a single issue.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum StateError {
    /// The `state.db` file (or its parent directory) could not be created or
    /// opened.
    #[error("could not open state.db at `{path}`")]
    #[diagnostic(
        code(vetinari::state::open),
        help(
            "Check that `.orchestrator/` is writable and not locked by another orchestrator process."
        )
    )]
    Open {
        /// Path the orchestrator tried to open.
        path: PathBuf,
        /// Underlying SQLite or I/O error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// A schema migration failed to apply, or the database is at a schema
    /// version newer than this binary understands.
    #[error("state.db migration to schema v{target_version} failed")]
    #[diagnostic(
        code(vetinari::state::migration),
        help("The schema is forward-only — never run an older orchestrator against a newer state.db. A failed migration leaves the database on its prior version.")
    )]
    Migration {
        /// Schema version the migration was advancing to.
        target_version: u32,
        /// Underlying cause.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// A read or write against `state.db` failed.
    #[error("state.db operation failed ({context})")]
    #[diagnostic(
        code(vetinari::state::query),
        help("`context` names the failing operation; the source carries the SQLite detail. An unrecognized enum value here means the database was written by a newer binary.")
    )]
    Query {
        /// Human-readable name of the failing operation, e.g. `upsert issue`.
        context: String,
        /// Underlying SQLite (or payload (de)serialization) error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

// ============================================================================
// Convenience constructors
// ============================================================================

impl SpawnError {
    /// Build an [`SpawnError::Io`] from a path + std I/O error.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        SpawnError::Io {
            path: path.into(),
            source,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_codes_are_unique() {
        // Compile-time-ish guard: if two variants share a code(...) it's a
        // copy-paste bug. Collected by hand because miette doesn't expose the
        // mapping at runtime.
        let codes = [
            "vetinari::spawn::claude_sandbox_version_mismatch",
            "vetinari::spawn::claude_sandbox_missing",
            "vetinari::spawn::zellij_session_unavailable",
            "vetinari::spawn::zellij_pane_create_failed",
            "vetinari::spawn::workspace_path_conflict",
            "vetinari::spawn::bwrap_failed",
            "vetinari::spawn::hook_config_missing",
            "vetinari::spawn::io",
            "vetinari::spawn::workspace_prep",
            "vetinari::qa::script_not_found",
            "vetinari::qa::script_unspawnable",
            "vetinari::qa::script_errored",
            "vetinari::qa::script_killed",
            "vetinari::qa::timed_out",
            "vetinari::landing::rebase_conflict",
            "vetinari::landing::push_conflict",
            "vetinari::landing::bookmark_move_failed",
            "vetinari::landing::gh_auth_missing",
            "vetinari::landing::pr_create_failed",
            "vetinari::landing::merger_invalid_result",
            "vetinari::landing::post_merge_qa_failed",
            "vetinari::landing::substate_inconsistent",
            "vetinari::recovery::unknown_substate",
            "vetinari::recovery::workspace_missing",
            "vetinari::recovery::state_db_inconsistent",
            "vetinari::recovery::jj_log_mismatch",
            "vetinari::artifact::done_missing",
            "vetinari::artifact::schema_violation",
            "vetinari::artifact::done_malformed",
            "vetinari::artifact::done_artifact_path_unsafe",
            "vetinari::artifact::done_artifact_missing",
            "vetinari::artifact::checksum_mismatch",
            "vetinari::artifact::read_failed",
            "vetinari::artifact::duplicate_posting",
            "vetinari::state::open",
            "vetinari::state::migration",
            "vetinari::state::query",
        ];
        let mut seen = std::collections::HashSet::new();
        for c in codes {
            assert!(seen.insert(c), "duplicate diagnostic code: {c}");
        }
    }

    #[test]
    fn errors_flow_through_question_mark() {
        fn level_one() -> Result<()> {
            Err(QaError::ScriptItselfErrored {
                exit_code: 127,
                message: "cargo: command not found\n".into(),
            }
            .into())
        }
        fn level_two() -> Result<()> {
            level_one()?;
            Ok(())
        }
        let err = level_two().unwrap_err();
        assert!(matches!(
            err,
            OrchestratorError::Qa(QaError::ScriptItselfErrored { .. })
        ));
    }

    #[test]
    fn artifact_schema_violation_renders_a_label() {
        let src = NamedSource::new(
            "findings.jsonl",
            "{\"severity\":\"high\"}\nbad-line-no-json\n".to_string(),
        );
        // line 2 starts at offset 21 (length of line 1 + newline) and is 16 chars.
        let err = ArtifactError::SchemaViolation {
            artifact: PathBuf::from("/tmp/x/findings.jsonl"),
            line_no: 2,
            src,
            offending: (21, 16).into(),
            source: serde_json::from_str::<serde_json::Value>("bad-line-no-json")
                .err()
                .map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                .expect("invalid json produces an error"),
        };
        let report = miette::Report::new(err);
        let rendered = format!("{report:?}");
        assert!(rendered.contains("schema violation"));
    }

    #[test]
    fn duplicate_posting_is_a_warning_not_an_error() {
        use miette::Diagnostic;
        let e = ArtifactError::DuplicatePosting {
            worker_uuid: "u".into(),
            artifact: PathBuf::from("x"),
            finding_index: 0,
        };
        assert_eq!(e.severity(), Some(miette::Severity::Warning));
    }
}
