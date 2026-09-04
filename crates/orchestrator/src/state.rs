//! SQLite-backed `state.db` — the orchestrator's authoritative state (REQ-2).
//!
//! Crosslink labels (`phase:*`, `round:N`) are a presentation layer; the
//! orchestrator's next-action decision reads from this database plus workspace
//! artifacts, never from labels. The schema is defined by [`MIGRATION_V1`] and
//! mirrors the table layout in `.design/vdd-orchestrator.md`.
//!
//! Four tables back four concerns:
//! - `issues` — per-issue phase, in-flight substate (REQ-2a) and convergence
//!   bookkeeping.
//! - `active_workers` — one row per live worker, for the watchdog and recovery.
//! - `posted_artifacts` — the idempotency ledger for comment translation
//!   (REQ-3b, AC-17): each `(issue, artifact-path, content-sha, finding-index)`
//!   tuple posts once. The dedup key is **content-addressed and issue-scoped**,
//!   NOT keyed on the worker uuid: recovery re-drives an issue under a fresh
//!   uuid, so keying on the uuid would let identical content post twice. The
//!   producing `worker_uuid` is retained as a non-key audit column.
//! - `events` — the SQLite mirror of `events.jsonl` for queryable observability.
//!
//! # Forward-only schema
//!
//! Migrations only ever move the schema forward. Opening a `state.db` whose
//! `user_version` is newer than this binary understands is a hard error —
//! never run an older orchestrator against a newer database.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};
use vetinari_error::StateError;

// ============================================================================
// String-backed enums
// ============================================================================

/// Generates a string-backed enum: each variant maps to the exact token stored
/// in a `TEXT` column. The generated type round-trips through SQLite via
/// `rusqlite`'s `ToSql`/`FromSql`, and `from_db_str` lets the recovery path
/// parse a raw column value without a hard read failure.
macro_rules! str_enum {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$var_meta:meta])* $variant:ident => $token:literal ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis enum $name {
            $( $(#[$var_meta])* $variant ),+
        }

        impl $name {
            /// The canonical token this variant is stored as in `state.db`.
            $vis fn as_str(&self) -> &'static str {
                match self { $( Self::$variant => $token ),+ }
            }

            /// Parse a raw value read back from `state.db`. Returns `None` for
            /// any token this binary does not recognize — callers on the
            /// recovery path turn that into a precise diagnostic.
            $vis fn from_db_str(s: &str) -> Option<Self> {
                match s {
                    $( $token => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl rusqlite::types::ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
                Ok(rusqlite::types::ToSqlOutput::from(self.as_str()))
            }
        }

        impl rusqlite::types::FromSql for $name {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                let raw = value.as_str()?;
                Self::from_db_str(raw).ok_or_else(|| {
                    rusqlite::types::FromSqlError::Other(
                        format!(
                            "state.db holds unrecognized {} value `{raw}`",
                            stringify!($name),
                        )
                        .into(),
                    )
                })
            }
        }
    };
}

str_enum! {
    /// Lifecycle phase of an issue, owned by the orchestrator's phase machine.
    pub enum Phase {
        /// Graphed and waiting for the build pump to pick it up.
        Graphed => "graphed",
        /// An Implementer worker is (or should be) running.
        Implementing => "implementing",
        /// The static QA gate is running or pending evaluation.
        QaGate => "qa-gate",
        /// An Adversary worker is reviewing the diff (iteration 2+).
        AdversaryReview => "adversary-review",
        /// The convergence criterion is met; about to land.
        Converged => "converged",
        /// The orchestrator is rebasing / pushing / opening a PR.
        Landing => "landing",
        /// Landed locally — terminal.
        Merged => "merged",
        /// A PR is open for the issue — terminal.
        PrOpen => "pr-open",
        /// Landing failed and needs a human merge — terminal until resumed.
        AwaitingHumanMerge => "awaiting-human-merge",
        /// A converged **`xb:inbound`** (untrusted-origin) issue, parked at the
        /// human trust-gate: it has passed implement → QA → adversary → converged
        /// but MUST NOT auto-land (REQ-SWARM-1). It stays here — a parked, terminal,
        /// non-drivable phase (the `AwaitingHumanMerge` model) — until a human adds
        /// the explicit `inbound-approved:land` label, which resumes it into
        /// landing. This is the single structural enforcement of the threat model's
        /// "untrusted origin ⇒ HARD NO-GO on auto-land", holding regardless of
        /// `tracker_remote` mode or any `auto_graph` policy.
        AwaitingInboundApproval => "awaiting-inbound-approval",
        /// An unrecoverable orchestrator-side fault — terminal.
        OrchestratorError => "orchestrator-error",
    }
}

impl Phase {
    /// Whether the build pump's drive step (REQ-2) may pick this phase up and
    /// drive it. Drivable = non-terminal and non-parked: an issue whose
    /// authoritative `state.db` phase is one of these is queued work.
    ///
    /// - `Graphed` — freshly ingested, never driven.
    /// - `Implementing` / `QaGate` — a requeued or crash-interrupted in-flight
    ///   worker phase; re-driven from `state.db` (fresh workspace, round++).
    ///
    /// Everything else is *not* driven by the pump:
    /// - `Merged` / `PrOpen` — terminal success.
    /// - `AwaitingHumanMerge` — parked for a human (REQ-15a resumes it via a
    ///   label, not the pump's poll).
    /// - `OrchestratorError` — poisoned; a human must inspect.
    /// - `AdversaryReview` / `Converged` / `Landing` — iteration-2+ / in-flight
    ///   landing substates not entered by the MVP drive loop; excluded so the
    ///   pump never re-enters a landing mid-flight (P2 recovery, #16, owns that).
    pub fn is_drivable(self) -> bool {
        matches!(self, Phase::Graphed | Phase::Implementing | Phase::QaGate)
    }

    /// Whether this phase is **terminal**: the issue's lifecycle has ended and
    /// neither the pump's drive step nor crash-recovery advances it further.
    ///
    /// This is the **single terminal-set definition**. The crossbridge answer-back
    /// trigger ([`crate::answer::phase_delivers_answer`]) and crash-recovery
    /// ([`crate::recovery`]'s `is_terminal`) both delegate here, so the two can
    /// never drift out of sync about what "terminal" means (a delivered answer and
    /// a recovery no-op must agree on the same set).
    ///
    /// **Step 6** (the human inbound gate) adds the `awaiting-inbound-approval`
    /// terminal here, as a single new arm — this is the one and only place the
    /// terminal set is enumerated, so that change touches exactly this function.
    ///
    /// `AwaitingInboundApproval` is a **parked terminal**: like `AwaitingHumanMerge`
    /// it is not driven and not advanced by the pump's drive step or by
    /// crash-recovery. Being in the terminal set makes the crossbridge answer-back
    /// trigger fire when an inbound issue parks here, so the source peer is answered
    /// once at the park (spec §1.3, "so a peer is never left waiting"); the
    /// label-gated resume back into landing is driven separately by the pump's
    /// approval sweep, not by the drive step (so `is_drivable` stays `false`).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Phase::Merged
                | Phase::PrOpen
                | Phase::AwaitingHumanMerge
                | Phase::AwaitingInboundApproval
                | Phase::OrchestratorError
        )
    }
}

str_enum! {
    /// In-flight substate of a multi-step phase (REQ-2a). Tracks progress
    /// through `qa-gate` and `landing` so a crash mid-phase is recoverable.
    pub enum PhaseSubstate {
        /// `qa-gate`: the static QA script is running.
        QaRunning => "qa_running",
        /// `qa-gate`: QA passed; the phase transition is not yet committed.
        QaPassedPendingTransition => "qa_passed_pending_transition",
        /// `landing`: `jj rebase` has started.
        RebaseStarted => "rebase_started",
        /// `landing`: rebase done; the bookmark move is pending.
        RebaseDoneBookmarkPending => "rebase_done_bookmark_pending",
        /// `landing`: the rebase conflicted and a Merger worker is resolving it
        /// (REQ-19). Persisted before the Merger spawn so a crash mid-merge is
        /// recoverable — the resume path parks for a human rather than blindly
        /// re-driving an in-flight resolution.
        Merging => "merging",
        /// `landing`: the bookmark has been moved.
        BookmarkMovedComplete => "bookmark_moved_complete",
        /// `landing`: `jj git push` has started.
        PushStarted => "push_started",
        /// `landing`: push done; PR creation is pending.
        PushDonePrPending => "push_done_pr_pending",
        /// `landing`: the PR has been created.
        PrCreated => "pr_created",

        // --- crossbridge answer-back (spec §1.3/§1.4) ---
        //
        // These substates ride a TERMINAL phase: an `xb:inbound` issue that has
        // reached `Merged`/`PrOpen`/`AwaitingHumanMerge`/`OrchestratorError`
        // carries one of these to track delivery of its worked result back to the
        // originating peer. Authority is this column, NEVER the `xb-status:*`
        // crosslink label (review B5 — that label is written incoherently by
        // three crossbridge binaries and is a courtesy mirror only).
        /// answer-back: the result is gathered and ready to send, but no
        /// `SubmitAnswer` has succeeded yet — the pump's answer sweep delivers it.
        AnswerPending => "answer_pending",
        /// answer-back: the `SubmitAnswer` round-trip succeeded — TERMINAL for the
        /// answer machine (recovery no-ops it; crossbridge source-side dedup means
        /// even a stray re-send would not double-answer).
        AnswerSent => "answer_sent",
        /// answer-back: the source peer could not be reached (offline / stalled /
        /// wire failure). A **degraded, non-terminal** waiting state — retried on
        /// poll ticks, rate-limited and bounded; a `--kind blocker` stands on the
        /// issue for human attention while it waits.
        AnswerUnreachable => "answer_unreachable",
    }
}

str_enum! {
    /// How the orchestrator decides an issue's review loop has converged.
    /// Read from `.orchestrator/config.toml` at transition time (REQ-2a) so a
    /// compile-time `cfg` never determines routing.
    pub enum ConvergenceMode {
        /// Converged after N consecutive empty Adversary rounds (MVP / it.2).
        NRounds => "n-rounds",
        /// Converged when a Judge worker says so (iteration 3+).
        Judge => "judge",
    }
}

str_enum! {
    /// The role a spawned worker plays.
    pub enum WorkerRole {
        /// Writes code against the issue (REQ-7).
        Implementer => "implementer",
        /// Reviews the Implementer's diff for findings (REQ-13).
        Adversary => "adversary",
        /// Decides convergence in iteration 3+ (stub in MVP).
        Judge => "judge",
        /// Resolves a rebase/push conflict (REQ-19).
        Merger => "merger",
    }
}

str_enum! {
    /// The kind of a row in the `events` table / `events.jsonl` mirror.
    pub enum EventKind {
        /// A worker was spawned.
        Spawn => "spawn",
        /// An issue moved between phases.
        Transition => "transition",
        /// The static QA gate produced a pass/fail result.
        QaResult => "qa_result",
        /// The watchdog killed a stalled worker.
        WatchdogKill => "watchdog_kill",
        /// A convergence decision was made.
        Convergence => "convergence",
    }
}

// ============================================================================
// Schema
// ============================================================================

/// Current `state.db` schema version. Bumped only by adding a new forward
/// migration; an existing version is never rewritten.
///
/// - v1 — the initial four-table set ([`MIGRATION_V1`]).
/// - v2 — adds `issues.answer_attempts` ([`MIGRATION_V2`]), the durable retry
///   counter the crossbridge answer-back state machine bounds against
///   (`.design/swarm-kickoff-spec.md` §1.3).
/// - v3 — adds `issues.landing_change` ([`MIGRATION_V3`]), the durable
///   converged-change handle an `xb:inbound` issue parked at
///   `awaiting-inbound-approval` (REQ-SWARM-1) is landed from once a human
///   approves it — persisted so the label-gated resume survives a restart.
const SCHEMA_VERSION: u32 = 3;

/// How long a connection waits out a transient SQLite lock before giving up
/// (D7). Applied to **both** openers:
///
/// - [`StateDb::open`] — the pump's **writer**. A second sanctioned writer now
///   exists (the embedded crossbridge server writes `.crosslink/issues.db`, and
///   this machine writes `state.db` from the same process), and a `state.db`
///   WAL checkpoint can briefly take an exclusive lock; without a busy_timeout a
///   momentary lock would surface as `SQLITE_BUSY` and fail a write mid-tick.
/// - [`StateDb::open_read_only`] — the `vetinari` query CLI (§2.2), so a
///   momentary exclusive lock never fails a read mid-query.
///
/// A reader in WAL mode does not take a lock the writer waits on; this timeout
/// only guards the brief exclusive moments (e.g. a checkpoint) either side sees.
const BUSY_TIMEOUT_MS: u64 = 5_000;

/// Schema v1 — the initial table set. Applied inside a single transaction by
/// [`StateDb::open`] when an empty (`user_version = 0`) database is opened.
const MIGRATION_V1: &str = r#"
CREATE TABLE issues (
  issue_id           TEXT PRIMARY KEY,
  phase              TEXT NOT NULL,
  phase_substate     TEXT,
  round              INTEGER NOT NULL DEFAULT 0,
  convergence_mode   TEXT NOT NULL DEFAULT 'n-rounds',
  empty_round_streak INTEGER NOT NULL DEFAULT 0,
  -- empty_round_streak reset rules:
  --   reset to 0 when: (a) findings.jsonl non-empty in any round,
  --                    (b) QA fails in any round,
  --                    (c) the Implementer is re-spawned for any reason
  --   incremented when: a clean Adversary round produces 0 findings. The change
  --                     under review is a fixed (immutable) commit id for the
  --                     whole review, so N clean re-review rounds == N clean
  --                     rounds on the SAME change; no diff-hash comparison gates
  --                     the increment in this synchronous model (see pump.rs
  --                     `on_clean_round`).
  -- last_diff_hash is RESERVED (currently unwritten by the convergence path):
  -- it would gate the streak only in a future async/concurrent model where the
  -- change could move mid-review. See REQ-10 follow-up.
  last_diff_hash      TEXT,
  landing_retry_count INTEGER NOT NULL DEFAULT 0,
  updated_at          INTEGER NOT NULL
);
-- NOTE: `answer_attempts` is added by MIGRATION_V2, not here, so an existing
-- v1 database upgrades forward rather than being rewritten.

CREATE TABLE posted_artifacts (
  issue_id      TEXT NOT NULL,
  artifact_path TEXT NOT NULL,
  content_sha   TEXT NOT NULL,
  finding_index INTEGER NOT NULL DEFAULT -1,
  -- worker_uuid is a NON-KEY audit column: it records which attempt/worker
  -- produced the posted comment, but the dedup key below is content-addressed
  -- and issue-scoped so a re-translation of identical content under a fresh
  -- uuid (crash recovery re-drive) still posts at most once (AC-17).
  worker_uuid   TEXT NOT NULL,
  comment_id    TEXT NOT NULL,
  posted_at     INTEGER NOT NULL,
  PRIMARY KEY (issue_id, artifact_path, content_sha, finding_index)
);

CREATE TABLE active_workers (
  worker_uuid    TEXT PRIMARY KEY,
  issue_id       TEXT NOT NULL,
  role           TEXT NOT NULL,
  round          INTEGER NOT NULL,
  workspace_path TEXT NOT NULL,
  pid            INTEGER,
  spawned_at     INTEGER NOT NULL,
  last_heartbeat INTEGER NOT NULL,
  FOREIGN KEY (issue_id) REFERENCES issues(issue_id)
);

CREATE TABLE events (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,
  kind        TEXT NOT NULL,
  issue_id    TEXT,
  worker_uuid TEXT,
  payload     TEXT NOT NULL
);
"#;

/// Schema v2 — the crossbridge answer-back retry counter
/// (`.design/swarm-kickoff-spec.md` §1.3). Adds one column to `issues`:
/// `answer_attempts`, the count of `SubmitAnswer` delivery attempts that have
/// failed for an `xb:inbound` issue. It is the durable bound the
/// `answer_unreachable` retry loop checks so a permanently-offline peer can
/// never make the sweep spin — after the bound is hit the issue REMAINS
/// `answer_unreachable` (blocker standing) rather than being retried forever.
///
/// The paired rate-limit clock reuses the existing `updated_at` column rather
/// than adding a second timestamp: once an inbound issue is terminal the answer
/// sweep is its *sole* writer, so every `set_phase_substate` /
/// `record_answer_unreachable` stamp of `updated_at` IS the last-attempt time,
/// and a separate column would only duplicate it. `answer_attempts` has no such
/// existing home, so it earns a column.
///
/// `ALTER TABLE … ADD COLUMN … DEFAULT 0` is a metadata-only change: existing
/// rows read back `0` with no table rewrite (forward-only, REQ-2).
const MIGRATION_V2: &str = r#"
ALTER TABLE issues ADD COLUMN answer_attempts INTEGER NOT NULL DEFAULT 0;
"#;

/// Schema v3 — the durable converged-change handle for the inbound human-gate
/// (`.design/swarm-kickoff-spec.md` §1.2, REQ-SWARM-1). Adds one **nullable**
/// column to `issues`: `landing_change`, the resolved jj change/commit id of the
/// reviewed change an `xb:inbound` issue converged on.
///
/// It is written the moment the approval gate parks a converged inbound issue at
/// `awaiting-inbound-approval` (the Implementer workspace is already forgotten by
/// then, so the reviewed change can no longer be re-derived from a workspace) and
/// read back when a human's `inbound-approved:land` label resumes it — so the pump
/// lands **exactly the reviewed change the human approved**, never a fresh
/// re-implementation, and the approval survives an orchestrator restart while
/// parked. `NULL` for every non-inbound issue and every inbound issue that has not
/// yet parked for approval.
///
/// `ALTER TABLE … ADD COLUMN` with no `NOT NULL`/default is a metadata-only change:
/// existing rows read back `NULL` with no table rewrite (forward-only, REQ-2).
const MIGRATION_V3: &str = r#"
ALTER TABLE issues ADD COLUMN landing_change TEXT;
"#;

// ============================================================================
// Row types
// ============================================================================

/// A row of the `issues` table — per-issue phase and convergence bookkeeping.
#[derive(Debug, Clone, PartialEq)]
pub struct IssueRow {
    /// Crosslink issue id, e.g. `"L3"` or `"#42"`.
    pub issue_id: String,
    /// Current lifecycle phase.
    pub phase: Phase,
    /// In-flight substate (REQ-2a), or `None` outside a multi-step phase.
    ///
    /// Held as the raw column string rather than a typed [`PhaseSubstate`] on
    /// purpose: the crash-recovery path must be able to *detect* a substate
    /// written by a newer binary and report
    /// [`vetinari_error::RecoveryError::UnknownSubstate`], instead of failing
    /// an opaque column read. Writers should go through [`StateDb::set_phase`],
    /// which only accepts a typed [`PhaseSubstate`].
    pub phase_substate: Option<String>,
    /// Current review round (0-based).
    pub round: i64,
    /// Convergence strategy in force for this issue.
    pub convergence_mode: ConvergenceMode,
    /// Consecutive empty Adversary rounds — see the reset rules in the schema.
    pub empty_round_streak: i64,
    /// SHA-256 of the round-N `jj diff`, for the round-stability check.
    pub last_diff_hash: Option<String>,
    /// Number of Merger spawns attempted for this issue (bounded by REQ-19).
    pub landing_retry_count: i64,
    /// Unix seconds of the last update to this row.
    pub updated_at: i64,
    /// Number of failed crossbridge `SubmitAnswer` delivery attempts for an
    /// `xb:inbound` issue (spec §1.3). `0` for every non-inbound issue. The
    /// `answer_unreachable` retry loop is bounded against this; paired with
    /// [`updated_at`](Self::updated_at) (the last-attempt clock) it rate-limits
    /// and caps the retry so a permanently-offline peer never makes the sweep
    /// spin.
    pub answer_attempts: i64,
    /// The resolved jj change/commit id an `xb:inbound` issue converged on, stored
    /// when the approval gate parks it at `awaiting-inbound-approval` (REQ-SWARM-1)
    /// so the label-gated resume lands **exactly that reviewed change** (never a
    /// fresh re-implementation) even across an orchestrator restart. `None` for
    /// every non-inbound issue and every inbound issue not yet parked for approval.
    pub landing_change: Option<String>,
}

impl IssueRow {
    /// A freshly-graphed issue: the given phase, every counter at its schema
    /// default, and `updated_at` stamped to now.
    pub fn new(issue_id: impl Into<String>, phase: Phase) -> Self {
        IssueRow {
            issue_id: issue_id.into(),
            phase,
            phase_substate: None,
            round: 0,
            convergence_mode: ConvergenceMode::NRounds,
            empty_round_streak: 0,
            last_diff_hash: None,
            landing_retry_count: 0,
            updated_at: now_unix(),
            answer_attempts: 0,
            landing_change: None,
        }
    }
}

/// A row of the `active_workers` table — one live worker.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveWorkerRow {
    /// Unique worker id (the orchestrator-minted UUID).
    pub worker_uuid: String,
    /// Issue the worker is acting on. Foreign key into `issues`.
    pub issue_id: String,
    /// The worker's role.
    pub role: WorkerRole,
    /// Review round the worker was spawned for.
    pub round: i64,
    /// Filesystem path of the worker's jj workspace.
    pub workspace_path: PathBuf,
    /// OS process id, once known.
    pub pid: Option<i64>,
    /// Unix seconds the worker was spawned.
    pub spawned_at: i64,
    /// Unix seconds of the worker's most recent heartbeat.
    pub last_heartbeat: i64,
}

/// A row of the `posted_artifacts` table — the REQ-3b / AC-17 idempotency
/// ledger.
///
/// The dedup key is `(issue_id, artifact_path, content_sha, finding_index)` —
/// content-addressed and issue-scoped. `worker_uuid` is a non-key audit column:
/// it records the producing attempt but does NOT participate in deduplication,
/// so a re-translation of identical content for the same issue under a fresh
/// uuid (a recovery re-drive) still posts at most once.
#[derive(Debug, Clone, PartialEq)]
pub struct PostedArtifact {
    /// Issue the comment was posted to — part of the content-addressed dedup key.
    pub issue_id: String,
    /// Artifact path within the worker's `_orchestrator/` directory.
    pub artifact_path: String,
    /// SHA-256 of the artifact's content at posting time.
    pub content_sha: String,
    /// Index of the finding within a multi-finding artifact; `-1` for a
    /// whole-file artifact such as `result.md`.
    pub finding_index: i64,
    /// Worker that produced the artifact — a non-key AUDIT column.
    pub worker_uuid: String,
    /// Crosslink comment id returned when the comment was posted.
    pub comment_id: String,
    /// Unix seconds the comment was posted.
    pub posted_at: i64,
}

/// A row of the `events` table — the queryable mirror of `events.jsonl`.
#[derive(Debug, Clone, PartialEq)]
pub struct EventRow {
    /// Autoincrement row id.
    pub id: i64,
    /// Unix seconds the event was recorded.
    pub ts: i64,
    /// Event kind.
    pub kind: EventKind,
    /// Issue the event concerns, if any.
    pub issue_id: Option<String>,
    /// Worker the event concerns, if any.
    pub worker_uuid: Option<String>,
    /// Free-form JSON payload.
    pub payload: serde_json::Value,
}

// ============================================================================
// StateDb
// ============================================================================

const ISSUE_COLUMNS: &str = "issue_id, phase, phase_substate, round, convergence_mode, \
     empty_round_streak, last_diff_hash, landing_retry_count, updated_at, answer_attempts, \
     landing_change";

const WORKER_COLUMNS: &str = "worker_uuid, issue_id, role, round, workspace_path, pid, \
     spawned_at, last_heartbeat";

/// A handle to the orchestrator's `state.db`.
///
/// Holds a single SQLite connection. Not `Sync`; the orchestrator drives its
/// tick loop on one thread, so the database has exactly one writer.
pub struct StateDb {
    conn: Connection,
}

impl StateDb {
    /// Open (creating if absent) the `state.db` at `path`, applying any
    /// pending schema migration. The parent directory is created if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<StateDb, StateError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(open_err(path))?;
            }
        }
        let conn = Connection::open(path).map_err(open_err(path))?;
        // WAL keeps a reader (e.g. the dashboard) from blocking the writer;
        // foreign-key enforcement is off by default and must be set per
        // connection so the active_workers -> issues reference is checked.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(open_err(path))?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(open_err(path))?;
        // D7: the writer sets a busy_timeout too, not only the read-only opener.
        // A second sanctioned writer now shares this process (the embedded
        // crossbridge server writes `.crosslink/issues.db`), and a `state.db` WAL
        // checkpoint can briefly hold an exclusive lock; without this a momentary
        // lock would surface as `SQLITE_BUSY` and fail a write mid-tick.
        conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))
            .map_err(open_err(path))?;
        let mut db = StateDb { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Open the `state.db` at `path` **read-only**, for a second reader — the
    /// `vetinari` query CLI (`.design/swarm-kickoff-spec.md` §2.2) — while the
    /// running orchestrator holds the primary WAL writer open.
    ///
    /// This constructor exists because [`StateDb::open`] *writes*: it creates
    /// the file if absent and runs pending migrations. A read-only introspection
    /// surface must never do either — writes stay through the pump so the
    /// single-writer invariant (REQ-3) holds. So this:
    ///
    /// - opens the connection with `SQLITE_OPEN_READ_ONLY` (no create, no
    ///   migration): every write or DDL a caller could reach is refused by
    ///   SQLite itself, not merely by convention;
    /// - sets a `busy_timeout` so a transient WAL lock from the live writer is
    ///   waited out rather than surfaced as `SQLITE_BUSY` — the pump's own
    ///   opener sets none, so this reader supplies its own discipline and never
    ///   blocks the writer (a reader in WAL mode does not take a lock the writer
    ///   waits on; the timeout only guards the brief exclusive moments such as a
    ///   checkpoint);
    /// - verifies the on-disk schema matches this binary **without migrating**,
    ///   degrading to a clear error against a newer/older `state.db` rather than
    ///   panicking or rewriting it.
    ///
    /// All the existing typed getters ([`get_issue`](Self::get_issue),
    /// [`list_issues`](Self::list_issues),
    /// [`list_active_workers`](Self::list_active_workers),
    /// [`recent_events`](Self::recent_events), …) work unchanged on the returned
    /// handle; only the mutating methods will fail (at the SQLite layer) if ever
    /// called, which the read-only CLI never does.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<StateDb, StateError> {
        let path = path.as_ref();
        // READ_ONLY drops the default CREATE flag: opening an absent file is an
        // error (a missing state.db is a real condition the CLI reports), and
        // every write path is rejected by SQLite. URI + NO_MUTEX mirror the
        // driver defaults `Connection::open` would otherwise apply.
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags).map_err(open_err(path))?;
        // Connection-local setting (PRAGMA busy_timeout / sqlite3_busy_timeout);
        // it configures this handle's lock-wait behaviour and writes nothing to
        // the database file.
        conn.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))
            .map_err(open_err(path))?;
        let db = StateDb { conn };
        db.verify_schema_version()?;
        Ok(db)
    }

    /// Confirm the on-disk `user_version` equals [`SCHEMA_VERSION`] **without**
    /// applying (or being able to apply) any migration — the read-only twin of
    /// [`migrate`](Self::migrate). A database written by a different orchestrator
    /// build (older or newer) yields a precise [`StateError::Migration`] the CLI
    /// prints, never a partial read or a panic.
    fn verify_schema_version(&self) -> Result<(), StateError> {
        let current: u32 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .map(|v| v as u32)
            .map_err(migration_err(SCHEMA_VERSION))?;
        if current != SCHEMA_VERSION {
            return Err(StateError::Migration {
                target_version: SCHEMA_VERSION,
                source: format!(
                    "state.db is at schema v{current}, but this build expects v{SCHEMA_VERSION}; \
                     the read-only CLI never migrates — run it with a matching orchestrator build"
                )
                .into(),
            });
        }
        Ok(())
    }

    /// Apply forward migrations until the schema reaches [`SCHEMA_VERSION`].
    fn migrate(&mut self) -> Result<(), StateError> {
        let current: u32 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .map(|v| v as u32)
            .map_err(migration_err(SCHEMA_VERSION))?;
        if current == SCHEMA_VERSION {
            return Ok(());
        }
        if current > SCHEMA_VERSION {
            return Err(StateError::Migration {
                target_version: SCHEMA_VERSION,
                source: format!(
                    "state.db is at schema v{current}, newer than this binary's v{SCHEMA_VERSION}"
                )
                .into(),
            });
        }
        if current < 1 {
            self.apply_migration(1, MIGRATION_V1)?;
        }
        if current < 2 {
            self.apply_migration(2, MIGRATION_V2)?;
        }
        if current < 3 {
            self.apply_migration(3, MIGRATION_V3)?;
        }
        Ok(())
    }

    /// Apply one migration script atomically and bump `user_version`.
    fn apply_migration(&mut self, version: u32, script: &str) -> Result<(), StateError> {
        let tx = self.conn.transaction().map_err(migration_err(version))?;
        tx.execute_batch(script).map_err(migration_err(version))?;
        tx.pragma_update(None, "user_version", version)
            .map_err(migration_err(version))?;
        tx.commit().map_err(migration_err(version))?;
        Ok(())
    }

    // --- issues -------------------------------------------------------------

    /// Insert a new issue, or replace an existing one wholesale.
    pub fn upsert_issue(&self, issue: &IssueRow) -> Result<(), StateError> {
        self.conn
            .execute(
                "INSERT INTO issues
                   (issue_id, phase, phase_substate, round, convergence_mode,
                    empty_round_streak, last_diff_hash, landing_retry_count, updated_at,
                    answer_attempts, landing_change)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(issue_id) DO UPDATE SET
                   phase               = excluded.phase,
                   phase_substate      = excluded.phase_substate,
                   round               = excluded.round,
                   convergence_mode    = excluded.convergence_mode,
                   empty_round_streak  = excluded.empty_round_streak,
                   last_diff_hash      = excluded.last_diff_hash,
                   landing_retry_count = excluded.landing_retry_count,
                   updated_at          = excluded.updated_at,
                   answer_attempts     = excluded.answer_attempts,
                   landing_change      = excluded.landing_change",
                params![
                    issue.issue_id,
                    issue.phase,
                    issue.phase_substate,
                    issue.round,
                    issue.convergence_mode,
                    issue.empty_round_streak,
                    issue.last_diff_hash,
                    issue.landing_retry_count,
                    issue.updated_at,
                    issue.answer_attempts,
                    issue.landing_change,
                ],
            )
            .map_err(query_err("upsert issue"))?;
        Ok(())
    }

    /// Fetch one issue by id.
    pub fn get_issue(&self, issue_id: &str) -> Result<Option<IssueRow>, StateError> {
        self.conn
            .query_row(
                &format!("SELECT {ISSUE_COLUMNS} FROM issues WHERE issue_id = ?1"),
                params![issue_id],
                map_issue_row,
            )
            .optional()
            .map_err(query_err("get issue"))
    }

    /// Fetch every issue, ordered by id.
    pub fn list_issues(&self) -> Result<Vec<IssueRow>, StateError> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {ISSUE_COLUMNS} FROM issues ORDER BY issue_id"
            ))
            .map_err(query_err("prepare list issues"))?;
        let rows = stmt
            .query_map([], map_issue_row)
            .map_err(query_err("query list issues"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(query_err("read issue row"))
    }

    /// Update an issue's phase and substate, stamping `updated_at` to now.
    pub fn set_phase(
        &self,
        issue_id: &str,
        phase: Phase,
        substate: Option<PhaseSubstate>,
    ) -> Result<(), StateError> {
        self.conn
            .execute(
                "UPDATE issues SET phase = ?1, phase_substate = ?2, updated_at = ?3 \
                 WHERE issue_id = ?4",
                params![phase, substate.map(|s| s.as_str()), now_unix(), issue_id],
            )
            .map_err(query_err("set issue phase"))?;
        Ok(())
    }

    /// Update only an issue's `phase_substate` (leaving its terminal `phase`
    /// intact), stamping `updated_at` to now — the crossbridge answer-back write
    /// (spec §1.3).
    ///
    /// [`set_phase`](Self::set_phase) always rewrites `phase`; the answer machine
    /// must NOT, because the answer substate rides an already-terminal phase
    /// (`Merged`/`PrOpen`/…). This is the trigger's `answer_pending` write and the
    /// success path's `answer_sent` write. The `updated_at` stamp doubles as the
    /// retry-rate-limit clock (see [`IssueRow::answer_attempts`]).
    pub fn set_phase_substate(
        &self,
        issue_id: &str,
        substate: Option<PhaseSubstate>,
    ) -> Result<(), StateError> {
        self.conn
            .execute(
                "UPDATE issues SET phase_substate = ?1, updated_at = ?2 WHERE issue_id = ?3",
                params![substate.map(|s| s.as_str()), now_unix(), issue_id],
            )
            .map_err(query_err("set issue phase_substate"))?;
        Ok(())
    }

    /// Persist the converged-change handle an `xb:inbound` issue is parked on at
    /// `awaiting-inbound-approval` (REQ-SWARM-1), stamping `updated_at` to now.
    ///
    /// Written the moment the approval gate parks the issue — **before** its phase
    /// is flipped to `awaiting-inbound-approval` — so the reviewed change is durable
    /// the instant the issue is observably parked, and the label-gated resume can
    /// always land exactly it (even after an orchestrator restart). A targeted
    /// `UPDATE` (not an `upsert_issue`) so it never disturbs the row's other
    /// columns, and `phase`/`phase_substate` here are intentionally left untouched.
    pub fn set_landing_change(&self, issue_id: &str, change: &str) -> Result<(), StateError> {
        self.conn
            .execute(
                "UPDATE issues SET landing_change = ?1, updated_at = ?2 WHERE issue_id = ?3",
                params![change, now_unix(), issue_id],
            )
            .map_err(query_err("set landing change"))?;
        Ok(())
    }

    /// Record a failed answer delivery: increment `answer_attempts`, set the
    /// substate to `answer_unreachable`, and stamp `updated_at` to now — all in
    /// one write. Returns the new attempt count (the bound is checked against it).
    ///
    /// The terminal `phase` is left untouched (the answer substate rides it). The
    /// stamped `updated_at` is the last-attempt clock the sweep's rate-limit reads.
    pub fn record_answer_unreachable(&self, issue_id: &str) -> Result<i64, StateError> {
        self.conn
            .execute(
                "UPDATE issues
                   SET answer_attempts = answer_attempts + 1,
                       phase_substate  = ?1,
                       updated_at      = ?2
                 WHERE issue_id = ?3",
                params![
                    PhaseSubstate::AnswerUnreachable.as_str(),
                    now_unix(),
                    issue_id
                ],
            )
            .map_err(query_err("record answer unreachable"))?;
        self.conn
            .query_row(
                "SELECT answer_attempts FROM issues WHERE issue_id = ?1",
                params![issue_id],
                |r| r.get(0),
            )
            .map_err(query_err("read answer_attempts"))
    }

    /// Retire an inbound issue's answer as **permanently undeliverable**: set
    /// `answer_unreachable` and raise `answer_attempts` to at least `attempts_floor`
    /// in one write, stamping `updated_at`. Returns the resulting attempt count.
    ///
    /// Unlike [`record_answer_unreachable`](Self::record_answer_unreachable) (a
    /// transient peer outage that is retried), this is for a failure a retry can
    /// **never** fix — e.g. an `xb-source:` slug that is not a valid crossbridge
    /// slug, so no socket path can be formed. Forcing the attempt count to the
    /// bound makes the sweep's `MAX_ANSWER_ATTEMPTS` guard park it immediately with
    /// its blocker standing, rather than burning a dozen doomed retry ticks. The
    /// `MAX(...)` floor keeps the write idempotent (a re-run never lowers the
    /// count). The terminal `phase` is left untouched (the substate rides it).
    pub fn retire_answer_unreachable(
        &self,
        issue_id: &str,
        attempts_floor: i64,
    ) -> Result<i64, StateError> {
        self.conn
            .execute(
                "UPDATE issues
                   SET answer_attempts = MAX(answer_attempts, ?1),
                       phase_substate  = ?2,
                       updated_at      = ?3
                 WHERE issue_id = ?4",
                params![
                    attempts_floor,
                    PhaseSubstate::AnswerUnreachable.as_str(),
                    now_unix(),
                    issue_id
                ],
            )
            .map_err(query_err("retire answer unreachable"))?;
        self.conn
            .query_row(
                "SELECT answer_attempts FROM issues WHERE issue_id = ?1",
                params![issue_id],
                |r| r.get(0),
            )
            .map_err(query_err("read answer_attempts"))
    }

    // --- active workers -----------------------------------------------------

    /// Insert a worker row, or replace it if the uuid already exists.
    pub fn upsert_worker(&self, worker: &ActiveWorkerRow) -> Result<(), StateError> {
        self.conn
            .execute(
                "INSERT INTO active_workers
                   (worker_uuid, issue_id, role, round, workspace_path, pid,
                    spawned_at, last_heartbeat)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(worker_uuid) DO UPDATE SET
                   issue_id       = excluded.issue_id,
                   role           = excluded.role,
                   round          = excluded.round,
                   workspace_path = excluded.workspace_path,
                   pid            = excluded.pid,
                   spawned_at     = excluded.spawned_at,
                   last_heartbeat = excluded.last_heartbeat",
                params![
                    worker.worker_uuid,
                    worker.issue_id,
                    worker.role,
                    worker.round,
                    worker.workspace_path.to_string_lossy(),
                    worker.pid,
                    worker.spawned_at,
                    worker.last_heartbeat,
                ],
            )
            .map_err(query_err("upsert worker"))?;
        Ok(())
    }

    /// Fetch one worker by uuid.
    pub fn get_worker(&self, worker_uuid: &str) -> Result<Option<ActiveWorkerRow>, StateError> {
        self.conn
            .query_row(
                &format!("SELECT {WORKER_COLUMNS} FROM active_workers WHERE worker_uuid = ?1"),
                params![worker_uuid],
                map_worker_row,
            )
            .optional()
            .map_err(query_err("get worker"))
    }

    /// Fetch every live worker, ordered by spawn time.
    pub fn list_active_workers(&self) -> Result<Vec<ActiveWorkerRow>, StateError> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {WORKER_COLUMNS} FROM active_workers ORDER BY spawned_at"
            ))
            .map_err(query_err("prepare list workers"))?;
        let rows = stmt
            .query_map([], map_worker_row)
            .map_err(query_err("query list workers"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(query_err("read worker row"))
    }

    /// Drop a worker row — called once the worker has exited and been reaped.
    pub fn remove_worker(&self, worker_uuid: &str) -> Result<(), StateError> {
        self.conn
            .execute(
                "DELETE FROM active_workers WHERE worker_uuid = ?1",
                params![worker_uuid],
            )
            .map_err(query_err("remove worker"))?;
        Ok(())
    }

    /// Record a fresh heartbeat timestamp for a worker (REQ-14, watchdog).
    pub fn touch_heartbeat(&self, worker_uuid: &str, ts: i64) -> Result<(), StateError> {
        self.conn
            .execute(
                "UPDATE active_workers SET last_heartbeat = ?1 WHERE worker_uuid = ?2",
                params![ts, worker_uuid],
            )
            .map_err(query_err("touch worker heartbeat"))?;
        Ok(())
    }

    // --- posted artifacts ---------------------------------------------------

    /// Record that a comment was posted for an artifact tuple. Returns `true`
    /// if this is the first time the tuple was seen, `false` if it was already
    /// recorded — the REQ-3b / AC-17 idempotency guard that makes comment
    /// translation safe to re-run after a crash.
    ///
    /// Dedup is on the content-addressed key `(issue_id, artifact_path,
    /// content_sha, finding_index)`; `worker_uuid` is written as an audit column
    /// only, so a re-translation of identical content under a fresh uuid (a
    /// recovery re-drive) is correctly suppressed.
    pub fn record_posted(&self, posted: &PostedArtifact) -> Result<bool, StateError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO posted_artifacts
                   (issue_id, artifact_path, content_sha, finding_index,
                    worker_uuid, comment_id, posted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    posted.issue_id,
                    posted.artifact_path,
                    posted.content_sha,
                    posted.finding_index,
                    posted.worker_uuid,
                    posted.comment_id,
                    posted.posted_at,
                ],
            )
            .map_err(query_err("record posted artifact"))?;
        Ok(changed == 1)
    }

    /// Whether a comment has already been posted for this artifact tuple. Keyed
    /// on the content-addressed `(issue_id, artifact_path, content_sha,
    /// finding_index)` tuple, NOT the producing worker uuid.
    pub fn is_posted(
        &self,
        issue_id: &str,
        artifact_path: &str,
        content_sha: &str,
        finding_index: i64,
    ) -> Result<bool, StateError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM posted_artifacts
                 WHERE issue_id = ?1 AND artifact_path = ?2
                   AND content_sha = ?3 AND finding_index = ?4",
                params![issue_id, artifact_path, content_sha, finding_index],
                |r| r.get(0),
            )
            .map_err(query_err("check posted artifact"))?;
        Ok(count > 0)
    }

    /// Every `posted_artifacts` ledger row for an issue, in insertion order — the
    /// observable record of which comments the pump translated (REQ-3b). Used by
    /// the adversary-loop tests to assert a finding's `--kind blocker` was posted
    /// exactly once (idempotent, content-addressed); a `finding_index >= 0` row is
    /// a per-finding blocker, `-1` a whole-file `result` comment.
    pub fn list_posted_artifacts(&self, issue_id: &str) -> Result<Vec<PostedArtifact>, StateError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT issue_id, artifact_path, content_sha, finding_index, worker_uuid, \
                 comment_id, posted_at FROM posted_artifacts WHERE issue_id = ?1 \
                 ORDER BY posted_at, finding_index",
            )
            .map_err(query_err("prepare list posted artifacts"))?;
        let rows = stmt
            .query_map(params![issue_id], |row| {
                Ok(PostedArtifact {
                    issue_id: row.get(0)?,
                    artifact_path: row.get(1)?,
                    content_sha: row.get(2)?,
                    finding_index: row.get(3)?,
                    worker_uuid: row.get(4)?,
                    comment_id: row.get(5)?,
                    posted_at: row.get(6)?,
                })
            })
            .map_err(query_err("query list posted artifacts"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(query_err("read posted artifact row"))
    }

    // --- events -------------------------------------------------------------

    /// Append an event, returning its new autoincrement `id` and the `ts` (unix
    /// seconds) stamped onto it.
    ///
    /// The `ts` is computed **once** here and returned so a caller mirroring the
    /// event elsewhere (e.g. [`crate::events::emit`] into `events.jsonl`) can
    /// carry the exact authoritative timestamp without re-querying the row — a
    /// re-query would risk substituting a second, divergent `now()`.
    pub fn append_event(
        &self,
        kind: EventKind,
        issue_id: Option<&str>,
        worker_uuid: Option<&str>,
        payload: &serde_json::Value,
    ) -> Result<(i64, i64), StateError> {
        let ts = now_unix();
        let payload =
            serde_json::to_string(payload).map_err(query_err("serialize event payload"))?;
        self.conn
            .execute(
                "INSERT INTO events (ts, kind, issue_id, worker_uuid, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ts, kind, issue_id, worker_uuid, payload],
            )
            .map_err(query_err("append event"))?;
        Ok((self.conn.last_insert_rowid(), ts))
    }

    /// The most recent `limit` events, newest first.
    pub fn recent_events(&self, limit: u32) -> Result<Vec<EventRow>, StateError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ts, kind, issue_id, worker_uuid, payload
                 FROM events ORDER BY id DESC LIMIT ?1",
            )
            .map_err(query_err("prepare recent events"))?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, EventKind>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(query_err("query recent events"))?;
        let mut events = Vec::new();
        for row in rows {
            let (id, ts, kind, issue_id, worker_uuid, payload) =
                row.map_err(query_err("read event row"))?;
            let payload =
                serde_json::from_str(&payload).map_err(query_err("deserialize event payload"))?;
            events.push(EventRow {
                id,
                ts,
                kind,
                issue_id,
                worker_uuid,
                payload,
            });
        }
        Ok(events)
    }

    /// Every event in the table, **oldest first** (ascending `id`).
    ///
    /// This is the authoritative, fully-ordered event stream — the source the
    /// [`crate::events::EventLog::rebuild_from`] reconciler rewrites the JSONL
    /// mirror from. [`recent_events`](Self::recent_events) can't express it (it
    /// caps at `limit` and orders newest-first), so a rebuild needs this instead.
    pub fn all_events(&self) -> Result<Vec<EventRow>, StateError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ts, kind, issue_id, worker_uuid, payload
                 FROM events ORDER BY id ASC",
            )
            .map_err(query_err("prepare all events"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, EventKind>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(query_err("query all events"))?;
        let mut events = Vec::new();
        for row in rows {
            let (id, ts, kind, issue_id, worker_uuid, payload) =
                row.map_err(query_err("read event row"))?;
            let payload =
                serde_json::from_str(&payload).map_err(query_err("deserialize event payload"))?;
            events.push(EventRow {
                id,
                ts,
                kind,
                issue_id,
                worker_uuid,
                payload,
            });
        }
        Ok(events)
    }
}

// ============================================================================
// Row mappers + helpers
// ============================================================================

/// Build an [`IssueRow`] from a result row selecting [`ISSUE_COLUMNS`] in order.
fn map_issue_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IssueRow> {
    Ok(IssueRow {
        issue_id: row.get(0)?,
        phase: row.get(1)?,
        phase_substate: row.get(2)?,
        round: row.get(3)?,
        convergence_mode: row.get(4)?,
        empty_round_streak: row.get(5)?,
        last_diff_hash: row.get(6)?,
        landing_retry_count: row.get(7)?,
        updated_at: row.get(8)?,
        answer_attempts: row.get(9)?,
        landing_change: row.get(10)?,
    })
}

/// Build an [`ActiveWorkerRow`] from a result row selecting [`WORKER_COLUMNS`].
fn map_worker_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActiveWorkerRow> {
    let workspace_path: String = row.get(4)?;
    Ok(ActiveWorkerRow {
        worker_uuid: row.get(0)?,
        issue_id: row.get(1)?,
        role: row.get(2)?,
        round: row.get(3)?,
        workspace_path: PathBuf::from(workspace_path),
        pid: row.get(5)?,
        spawned_at: row.get(6)?,
        last_heartbeat: row.get(7)?,
    })
}

/// Current time as unix seconds. A clock before the epoch yields `0` rather
/// than panicking — `state.db` only needs a monotone-ish ordering hint.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Closure that wraps an error into [`StateError::Open`] for a given path.
fn open_err<E>(path: &Path) -> impl Fn(E) -> StateError + '_
where
    E: std::error::Error + Send + Sync + 'static,
{
    move |e| StateError::Open {
        path: path.to_path_buf(),
        source: Box::new(e),
    }
}

/// Closure that wraps an error into [`StateError::Query`] with an operation
/// name. Generic so it serves both `rusqlite` and `serde_json` failures.
fn query_err<E>(context: &'static str) -> impl Fn(E) -> StateError
where
    E: std::error::Error + Send + Sync + 'static,
{
    move |e| StateError::Query {
        context: context.to_string(),
        source: Box::new(e),
    }
}

/// Closure that wraps a `rusqlite` error into [`StateError::Migration`].
fn migration_err(target_version: u32) -> impl Fn(rusqlite::Error) -> StateError {
    move |e| StateError::Migration {
        target_version,
        source: Box::new(e),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (tempfile::TempDir, StateDb) {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = StateDb::open(dir.path().join("state.db")).expect("open state.db");
        (dir, db)
    }

    #[test]
    fn migration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        StateDb::open(&path).expect("first open");
        // Reopening an already-migrated db is a no-op, not an error.
        StateDb::open(&path).expect("second open");
    }

    #[test]
    fn open_read_only_reads_a_live_writers_rows_without_migrating() {
        // Mirrors the deployed shape: the pump holds the WAL writer open while
        // the `vetinari` CLI opens a SECOND, read-only connection concurrently.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let writer = StateDb::open(&path).expect("writer open");
        writer
            .upsert_issue(&IssueRow::new("7", Phase::Implementing))
            .unwrap();

        // Reader opens while the writer is still alive.
        let reader = StateDb::open_read_only(&path).expect("read-only open");
        assert_eq!(
            reader.get_issue("7").unwrap().map(|i| i.phase),
            Some(Phase::Implementing)
        );

        // A write attempted through the read-only handle is refused by SQLite
        // itself — the invariant the CLI leans on.
        let write_err = reader.upsert_issue(&IssueRow::new("8", Phase::Graphed));
        assert!(
            write_err.is_err(),
            "a read-only connection must reject every write"
        );
        // The writer's own row set is unchanged — nothing leaked through.
        assert_eq!(writer.list_issues().unwrap().len(), 1);
    }

    #[test]
    fn open_read_only_rejects_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        // No state.db was ever created (READ_ONLY does not create).
        // `StateDb` is not `Debug`, so match on the Result rather than
        // `unwrap_err` (which would require `T: Debug`).
        assert!(matches!(
            StateDb::open_read_only(dir.path().join("absent.db")),
            Err(StateError::Open { .. })
        ));
    }

    #[test]
    fn open_read_only_reads_after_the_writer_closed() {
        // The "stopped node" case: the orchestrator is not running, so the CLI
        // reads a checkpointed WAL database with no live writer.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let writer = StateDb::open(&path).expect("writer open");
            writer
                .upsert_issue(&IssueRow::new("42", Phase::Converged))
                .unwrap();
            // writer dropped here → connection closed, WAL checkpointed.
        }
        let reader = StateDb::open_read_only(&path).expect("read-only open after close");
        assert_eq!(
            reader.get_issue("42").unwrap().map(|i| i.phase),
            Some(Phase::Converged)
        );
    }

    #[test]
    fn issue_round_trips() {
        let (_dir, db) = temp_db();
        let mut issue = IssueRow::new("#42", Phase::Implementing);
        issue.round = 3;
        issue.empty_round_streak = 2;
        issue.last_diff_hash = Some("abc123".into());
        issue.phase_substate = Some(PhaseSubstate::QaRunning.as_str().to_string());
        db.upsert_issue(&issue).unwrap();
        assert_eq!(db.get_issue("#42").unwrap().as_ref(), Some(&issue));
        assert_eq!(db.list_issues().unwrap(), vec![issue]);
    }

    #[test]
    fn upsert_issue_replaces_existing_row() {
        let (_dir, db) = temp_db();
        db.upsert_issue(&IssueRow::new("#1", Phase::Graphed))
            .unwrap();
        let mut updated = IssueRow::new("#1", Phase::Implementing);
        updated.round = 7;
        db.upsert_issue(&updated).unwrap();
        let stored = db.get_issue("#1").unwrap().unwrap();
        assert_eq!(stored.phase, Phase::Implementing);
        assert_eq!(stored.round, 7);
        assert_eq!(db.list_issues().unwrap().len(), 1);
    }

    #[test]
    fn set_phase_updates_phase_and_substate() {
        let (_dir, db) = temp_db();
        db.upsert_issue(&IssueRow::new("#1", Phase::QaGate))
            .unwrap();
        db.set_phase("#1", Phase::Landing, Some(PhaseSubstate::RebaseStarted))
            .unwrap();
        let issue = db.get_issue("#1").unwrap().unwrap();
        assert_eq!(issue.phase, Phase::Landing);
        assert_eq!(issue.phase_substate.as_deref(), Some("rebase_started"));
        // Clearing the substate back to NULL must also work.
        db.set_phase("#1", Phase::Merged, None).unwrap();
        assert_eq!(db.get_issue("#1").unwrap().unwrap().phase_substate, None);
    }

    #[test]
    fn answer_setters_track_substate_and_attempts_without_touching_phase() {
        let (_dir, db) = temp_db();
        // An inbound issue that reached a terminal phase (Merged) — the answer
        // machine only ever writes its substate/attempts, never its phase.
        db.upsert_issue(&IssueRow::new("5", Phase::Merged)).unwrap();

        // Trigger: mark answer_pending. Phase stays Merged.
        db.set_phase_substate("5", Some(PhaseSubstate::AnswerPending))
            .unwrap();
        let row = db.get_issue("5").unwrap().unwrap();
        assert_eq!(row.phase, Phase::Merged);
        assert_eq!(row.phase_substate.as_deref(), Some("answer_pending"));
        assert_eq!(row.answer_attempts, 0);

        // A failed delivery: attempts climb, substate flips to unreachable, phase
        // is still Merged.
        assert_eq!(db.record_answer_unreachable("5").unwrap(), 1);
        assert_eq!(db.record_answer_unreachable("5").unwrap(), 2);
        let row = db.get_issue("5").unwrap().unwrap();
        assert_eq!(row.phase, Phase::Merged);
        assert_eq!(row.phase_substate.as_deref(), Some("answer_unreachable"));
        assert_eq!(row.answer_attempts, 2);

        // Success: substate → answer_sent (attempts untouched), phase intact.
        db.set_phase_substate("5", Some(PhaseSubstate::AnswerSent))
            .unwrap();
        let row = db.get_issue("5").unwrap().unwrap();
        assert_eq!(row.phase, Phase::Merged);
        assert_eq!(row.phase_substate.as_deref(), Some("answer_sent"));
        assert_eq!(row.answer_attempts, 2);
    }

    #[test]
    fn set_landing_change_persists_the_converged_handle_without_touching_phase() {
        let (_dir, db) = temp_db();
        // A converged inbound issue about to park for approval (REQ-SWARM-1).
        db.upsert_issue(&IssueRow::new("7", Phase::Converged))
            .unwrap();
        assert_eq!(db.get_issue("7").unwrap().unwrap().landing_change, None);

        // The gate stores the reviewed change, then (separately) parks the phase.
        db.set_landing_change("7", "zzqqrr").unwrap();
        let row = db.get_issue("7").unwrap().unwrap();
        assert_eq!(row.landing_change.as_deref(), Some("zzqqrr"));
        assert_eq!(
            row.phase,
            Phase::Converged,
            "the setter must not move phase"
        );

        // Parking the phase leaves the stored change intact (set_phase is a
        // targeted UPDATE that never clears landing_change) — so the resume can
        // still find the reviewed change.
        db.set_phase("7", Phase::AwaitingInboundApproval, None)
            .unwrap();
        let row = db.get_issue("7").unwrap().unwrap();
        assert_eq!(row.phase, Phase::AwaitingInboundApproval);
        assert_eq!(row.landing_change.as_deref(), Some("zzqqrr"));
    }

    #[test]
    fn posted_artifacts_are_idempotent() {
        let (_dir, db) = temp_db();
        let posted = PostedArtifact {
            issue_id: "42".into(),
            artifact_path: "_orchestrator/findings.jsonl".into(),
            content_sha: "sha".into(),
            finding_index: 0,
            worker_uuid: "w1".into(),
            comment_id: "c1".into(),
            posted_at: 100,
        };
        assert!(db.record_posted(&posted).unwrap(), "first insert is new");
        assert!(
            !db.record_posted(&posted).unwrap(),
            "second insert of the same tuple is a no-op"
        );
        assert!(db
            .is_posted("42", "_orchestrator/findings.jsonl", "sha", 0)
            .unwrap());
        assert!(!db
            .is_posted("42", "_orchestrator/findings.jsonl", "sha", 1)
            .unwrap());
    }

    #[test]
    fn posted_artifacts_dedup_is_content_addressed_not_uuid_keyed() {
        // The AC-17 property: identical content for the SAME issue posted under
        // a DIFFERENT worker uuid (a recovery re-drive) is a dedup no-op — the
        // uuid is an audit column, not part of the key.
        let (_dir, db) = temp_db();
        let first = PostedArtifact {
            issue_id: "42".into(),
            artifact_path: "_orchestrator/result.md".into(),
            content_sha: "sha".into(),
            finding_index: -1,
            worker_uuid: "crashed-uuid".into(),
            comment_id: "c1".into(),
            posted_at: 100,
        };
        assert!(db.record_posted(&first).unwrap(), "first insert is new");
        // Same issue + content, fresh uuid (the redrive) → suppressed.
        let redrive = PostedArtifact {
            worker_uuid: "fresh-uuid".into(),
            comment_id: "c2".into(),
            ..first.clone()
        };
        assert!(
            !db.record_posted(&redrive).unwrap(),
            "identical content under a fresh uuid must be a dedup no-op (AC-17)"
        );
        assert!(db
            .is_posted("42", "_orchestrator/result.md", "sha", -1)
            .unwrap());
    }

    #[test]
    fn worker_lifecycle() {
        let (_dir, db) = temp_db();
        db.upsert_issue(&IssueRow::new("#7", Phase::Implementing))
            .unwrap();
        let worker = ActiveWorkerRow {
            worker_uuid: "uuid-1".into(),
            issue_id: "#7".into(),
            role: WorkerRole::Implementer,
            round: 0,
            workspace_path: PathBuf::from("/tmp/ws/implement-7"),
            pid: Some(4321),
            spawned_at: 10,
            last_heartbeat: 10,
        };
        db.upsert_worker(&worker).unwrap();
        assert_eq!(db.get_worker("uuid-1").unwrap().as_ref(), Some(&worker));
        db.touch_heartbeat("uuid-1", 99).unwrap();
        assert_eq!(db.get_worker("uuid-1").unwrap().unwrap().last_heartbeat, 99);
        db.remove_worker("uuid-1").unwrap();
        assert!(db.get_worker("uuid-1").unwrap().is_none());
        assert!(db.list_active_workers().unwrap().is_empty());
    }

    #[test]
    fn events_append_and_read_back() {
        let (_dir, db) = temp_db();
        let (id, ts) = db
            .append_event(
                EventKind::Transition,
                Some("#9"),
                None,
                &serde_json::json!({"from": "graphed", "to": "implementing"}),
            )
            .unwrap();
        assert!(id > 0);
        let events = db.recent_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::Transition);
        assert_eq!(events[0].issue_id.as_deref(), Some("#9"));
        assert_eq!(events[0].payload["to"], "implementing");
        assert_eq!(
            events[0].ts, ts,
            "append_event returns the same ts it stamped on the row"
        );
    }

    #[test]
    fn all_events_returns_full_stream_oldest_first() {
        let (_dir, db) = temp_db();
        for i in 0..4 {
            db.append_event(
                EventKind::Spawn,
                Some(&format!("#{i}")),
                None,
                &serde_json::json!({"n": i}),
            )
            .unwrap();
        }
        let all = db.all_events().unwrap();
        assert_eq!(all.len(), 4);
        // Oldest first: ids strictly ascending, payload counter in insert order.
        for (i, ev) in all.iter().enumerate() {
            assert_eq!(ev.payload["n"], i as i64);
        }
        assert!(all.windows(2).all(|w| w[0].id < w[1].id));
    }

    #[test]
    fn unknown_enum_value_is_rejected_on_read() {
        let (_dir, db) = temp_db();
        // Simulate a row written by a future binary with a phase this one
        // does not know. The typed read must fail rather than silently coerce.
        db.conn
            .execute(
                "INSERT INTO issues (issue_id, phase, updated_at) \
                 VALUES ('#x', 'time-travel', 0)",
                [],
            )
            .unwrap();
        let err = db.get_issue("#x").unwrap_err();
        assert!(matches!(err, StateError::Query { .. }));
    }

    #[test]
    fn foreign_key_rejects_worker_for_missing_issue() {
        let (_dir, db) = temp_db();
        let worker = ActiveWorkerRow {
            worker_uuid: "u".into(),
            issue_id: "#missing".into(),
            role: WorkerRole::Adversary,
            round: 1,
            workspace_path: PathBuf::from("/tmp/ws"),
            pid: None,
            spawned_at: 0,
            last_heartbeat: 0,
        };
        assert!(
            db.upsert_worker(&worker).is_err(),
            "the active_workers -> issues foreign key must be enforced"
        );
    }
}
