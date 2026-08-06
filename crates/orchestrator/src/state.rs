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
const SCHEMA_VERSION: u32 = 1;

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
     empty_round_streak, last_diff_hash, landing_retry_count, updated_at";

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
        let mut db = StateDb { conn };
        db.migrate()?;
        Ok(db)
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
                    empty_round_streak, last_diff_hash, landing_retry_count, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(issue_id) DO UPDATE SET
                   phase               = excluded.phase,
                   phase_substate      = excluded.phase_substate,
                   round               = excluded.round,
                   convergence_mode    = excluded.convergence_mode,
                   empty_round_streak  = excluded.empty_round_streak,
                   last_diff_hash      = excluded.last_diff_hash,
                   landing_retry_count = excluded.landing_retry_count,
                   updated_at          = excluded.updated_at",
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
