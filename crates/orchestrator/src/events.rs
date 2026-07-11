//! The append-only `events.jsonl` log and the heartbeat observability reader
//! (REQ-14, AC-9, AC-14).
//!
//! The orchestrator's state is observable from *outside* the sandbox via a
//! triplet (REQ-14): (a) `.orchestrator/events.jsonl`, an append-only machine
//! log; (b) per-worker `.orchestrator/heartbeat-<uuid>.json`; and (c) the
//! crosslink narrative trail. This module owns (a) the JSONL writer and (b) the
//! heartbeat *reader* + staleness check. It does **not** own the crosslink
//! trail (that is `crosslink.rs`), and it never *writes* heartbeats — workers
//! do that through a PostToolUse hook (REQ-11); the orchestrator only reads.
//!
//! # `events.jsonl` mirrors the SQLite `events` table
//!
//! The design keeps two copies of the event stream on purpose: the SQLite
//! `events` table ([`crate::state`]) is the queryable source of truth, and
//! `events.jsonl` is the line-oriented mirror a human tails with
//! `tail -f events.jsonl | jq .`. [`emit`] writes both from one call so they
//! stay consistent, with SQLite as the authority — see its docs for the crash
//! ordering. The event taxonomy ([`EventKind`]) and the row shape
//! ([`EventRow`]) are **reused** from [`crate::state`], never redefined, so the
//! two mirrors can never drift into different vocabularies.
//!
//! # Append-only by construction
//!
//! [`EventLog::open`] opens the file in append mode and the normal write path
//! ([`EventLog::append`]) exposes no `truncate`, `seek`, or `set_len` — there is
//! no method through which an earlier line can be rewritten. A crash
//! mid-`append` can leave a torn *trailing* line, but never corrupts an earlier
//! one (each `append` is a single buffered write of one complete line followed
//! by a flush), and readers tolerate that torn *tail* by skipping a final line
//! that does not parse (see [`read_all`], which surfaces an *interior*
//! corruption instead of hiding it).
//!
//! The single sanctioned exception is [`EventLog::rebuild_from`], the reconciler
//! (below): it truncates and rewrites the whole mirror from the authoritative
//! SQLite stream. It is a separate, explicitly-named constructor so the normal
//! append path stays append-only — no `append` caller can reach a truncating
//! handle.
//!
//! # Reconciliation from SQLite
//!
//! Because [`emit`] writes SQLite *first*, a torn or missing JSONL tail leaves
//! the mirror behind the authority with no in-band way to catch up on the
//! append path. [`EventLog::rebuild_from`] closes that gap: the orchestrator
//! calls it at startup to rebuild `events.jsonl` from the SQLite `events` table
//! (the source of truth), so a desynced mirror is repaired before the tick loop
//! resumes appending.
//!
//! # No shell-out (AC-24)
//!
//! Serialization is [`serde_json`]; all file access is [`std::fs`]/[`std::io`].
//! Nothing here constructs a `std::process::Command`.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vetinari_error::StateError;

use crate::state::{EventKind, EventRow, StateDb};

/// The orchestrator-private directory holding `state.db`, `events.jsonl`, and
/// the per-worker heartbeat files. Kept as a constant so the layout in
/// `.design/vdd-orchestrator.md` and the code agree.
pub const ORCHESTRATOR_DIR: &str = ".orchestrator";

/// The append-only machine log filename, relative to [`ORCHESTRATOR_DIR`].
pub const EVENTS_FILE: &str = "events.jsonl";

// ============================================================================
// JSONL wire shape
// ============================================================================

/// The exact JSON shape of one `events.jsonl` line (AC-9).
///
/// This mirrors [`EventRow`] minus its SQLite autoincrement `id`: the `id` is a
/// per-database detail, not part of the observable log, so it is deliberately
/// omitted. `kind` is serialized as its canonical token (e.g. `"transition"`),
/// matching the string stored in the SQLite `events.kind` column, so a value
/// tailed out of the JSONL and a value read back from SQLite are spelled
/// identically.
///
/// Private on purpose: callers construct events as typed [`EventRow`]s and let
/// [`EventLog::append`] handle the wire encoding, so no un-typed line can be
/// appended.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EventLine {
    /// Unix seconds the event was recorded.
    ts: i64,
    /// Event kind token (the same token the SQLite `events.kind` column holds).
    kind: String,
    /// Issue the event concerns, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    issue_id: Option<String>,
    /// Worker the event concerns, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    worker_uuid: Option<String>,
    /// Free-form JSON payload — e.g. an AC-9 transition's
    /// `{from_phase, to_phase, reason}`.
    payload: serde_json::Value,
}

impl EventLine {
    /// Project an [`EventRow`] onto the wire shape, dropping the SQLite `id`.
    fn from_row(row: &EventRow) -> Self {
        EventLine {
            ts: row.ts,
            kind: row.kind.as_str().to_owned(),
            issue_id: row.issue_id.clone(),
            worker_uuid: row.worker_uuid.clone(),
            payload: row.payload.clone(),
        }
    }
}

// ============================================================================
// EventLog — the append-only writer
// ============================================================================

/// An append-only writer for `.orchestrator/events.jsonl` (REQ-14, AC-9).
///
/// # Append-only invariant
///
/// The file is opened with [`OpenOptions::append`], so every write lands at the
/// current end of file regardless of any notion of a cursor, and the type
/// exposes no `truncate`/`seek`/`set_len` method. There is thus no public path
/// by which an already-written line can be overwritten or the file rewound —
/// "rewrite an earlier event" is unrepresentable through this API.
///
/// # Crash safety
///
/// [`append`](EventLog::append) serializes one event to a single `String`
/// (terminated by `\n`), writes that whole buffer in one `write_all`, then
/// flushes. The OS may still tear that final write on a crash, leaving a
/// partial trailing line — that is acceptable and documented: it never damages
/// an earlier, already-flushed line, and every reader here
/// ([`read_all`]/[`tail`]) skips a line that fails to parse, so a torn tail is
/// invisible to consumers. Earlier lines, having been flushed before the next
/// `append` began, are durable up to the OS page cache.
///
/// # Concurrency
///
/// The orchestrator is single-writer (one tick loop), but the inner writer sits
/// behind a [`Mutex`] so that even a stray concurrent `append` cannot interleave
/// two half-lines: each `append` holds the lock across its write-plus-flush, so
/// lines are always whole and never interleaved.
pub struct EventLog {
    /// Absolute path of the log, kept for error context.
    path: PathBuf,
    /// The append-mode handle behind a buffer, guarded so a single `append`'s
    /// write+flush is atomic against any other `append`.
    writer: Mutex<BufWriter<File>>,
}

impl EventLog {
    /// Open (creating if absent) the append-only log under `orchestrator_dir`
    /// (i.e. at `<orchestrator_dir>/events.jsonl`). The directory is created if
    /// needed. The file is opened in **append** mode and is **never**
    /// truncated, so re-opening a log preserves every prior line.
    pub fn open(orchestrator_dir: impl AsRef<Path>) -> Result<EventLog, StateError> {
        let dir = orchestrator_dir.as_ref();
        std::fs::create_dir_all(dir).map_err(open_err(dir))?;
        let path = dir.join(EVENTS_FILE);
        Self::open_file(path)
    }

    /// Open the log at an explicit file path (its parent is created if needed).
    /// Split from [`open`](EventLog::open) so tests can target a bare file and
    /// so a caller that already holds the full path need not re-derive it.
    pub fn open_file(path: impl Into<PathBuf>) -> Result<EventLog, StateError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(open_err(parent))?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(open_err(&path))?;
        Ok(EventLog {
            path,
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    /// The log's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append exactly one line of compact JSON for `event`, terminated by `\n`,
    /// and flush so an external `tail -f | jq .` observes it immediately (AC-9).
    ///
    /// The line is built fully in memory first, then written in a single
    /// `write_all` under the lock: a crash can only ever tear this one trailing
    /// line, never an earlier one. The SQLite `id` on `event` is not written —
    /// see [`EventLine`].
    pub fn append(&self, event: &EventRow) -> Result<(), StateError> {
        // Serialize into an owned line up front so the whole record hits the
        // writer in one `write_all` — a partial write can then only ever affect
        // this single trailing line.
        let mut line = serde_json::to_string(&EventLine::from_row(event))
            .map_err(query_err("serialize events.jsonl line"))?;
        line.push('\n');
        // Recover a poisoned lock rather than wedging observability forever: a
        // panic in another `append` cannot leave the buffer in a torn state (a
        // line is written whole-or-not under the lock), so the inner writer is
        // still usable.
        let mut writer = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        writer
            .write_all(line.as_bytes())
            .map_err(write_err(&self.path))?;
        // Flush the BufWriter so `tail -f` sees the line now, not at some later
        // buffer boundary. This is a userspace flush, not an fsync: durability
        // is bounded by the OS page cache, which the crash-safety contract
        // explicitly accepts (a torn tail is tolerated by readers).
        writer.flush().map_err(write_err(&self.path))?;
        Ok(())
    }

    /// Rebuild `events.jsonl` from `state` — the SQLite `events` table is the
    /// source of truth, so this **truncates and rewrites** the whole mirror from
    /// [`StateDb::all_events`], in `id` order.
    ///
    /// # Why this exists (the reconciler)
    ///
    /// [`emit`] writes SQLite first, then the JSONL. If the process dies between
    /// those two writes — or a JSONL append itself fails after the SQLite commit
    /// — the mirror is left short of, or torn against, the authority, and the
    /// append-only path has (by design) no way to rewrite an earlier line to fix
    /// it. This method is that repair path: the orchestrator calls it at startup
    /// so a torn or desynced `events.jsonl` is reconstructed exactly from the
    /// authoritative SQLite stream before the tick loop resumes appending.
    ///
    /// # The one sanctioned non-append rewrite
    ///
    /// This is the **only** method that does not append — it opens the file with
    /// `truncate` and rewrites it end to end. It is deliberately a separate,
    /// explicitly-named constructor so the normal [`EventLog`] returned by
    /// [`open`](EventLog::open) keeps its append-only-by-construction property:
    /// no `append` caller can reach a truncating handle. The returned
    /// [`EventLog`] is a fresh append-mode handle positioned at the end of the
    /// freshly-written file, ready for normal appends.
    pub fn rebuild_from(
        state: &StateDb,
        orchestrator_dir: impl AsRef<Path>,
    ) -> Result<EventLog, StateError> {
        let dir = orchestrator_dir.as_ref();
        std::fs::create_dir_all(dir).map_err(open_err(dir))?;
        let path = dir.join(EVENTS_FILE);

        // Build the full replacement body in memory from the authority, then
        // write it in one shot under a truncating open. Reusing `EventLine`
        // keeps the rewritten lines byte-identical to what `append` would emit.
        let events = state.all_events()?;
        let mut body = String::new();
        for event in &events {
            let line = serde_json::to_string(&EventLine::from_row(event))
                .map_err(query_err("serialize events.jsonl line"))?;
            body.push_str(&line);
            body.push('\n');
        }
        std::fs::write(&path, body).map_err(write_err(&path))?;

        // Hand back a normal append-only handle so the caller resumes appending.
        Self::open_file(path)
    }
}

/// Read every well-formed event line from a `events.jsonl` at `path`, in file
/// order.
///
/// The crash-safety contract only promises tolerance of a **torn trailing
/// line** (the one an interrupted `append` can leave, since each `append` writes
/// one whole line): that final line — if it fails to parse — is skipped
/// silently, as are blank lines anywhere. But an unparseable **interior** line
/// is *not* a documented outcome of the append-only writer; it signals real
/// corruption, and silently dropping it would under-count the mirror against
/// SQLite with no signal. So an interior parse failure is **surfaced** as
/// [`StateError::Query`] naming the 1-based line number, which the reconciler
/// ([`EventLog::rebuild_from`]) can act on by rewriting the JSONL from the
/// authoritative SQLite stream.
///
/// A missing file reads as an empty log. Returns the parsed rows with `id = 0` —
/// the JSONL carries no autoincrement id ([`EventLine`]); SQLite is the source
/// of that.
pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<EventRow>, StateError> {
    let path = path.as_ref();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => return Err(open_err(path)(source)),
    };
    let lines: Vec<&str> = content.lines().collect();
    let last_idx = lines.len().saturating_sub(1);
    let mut out = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let is_last = idx == last_idx;
        let Ok(parsed) = serde_json::from_str::<EventLine>(line) else {
            // Only the final line may be a torn tail. An unparseable interior
            // line is real corruption — surface it so the reconciler repairs.
            if is_last {
                continue;
            }
            return Err(corrupt_line_err(path, idx + 1));
        };
        let Some(kind) = EventKind::from_db_str(&parsed.kind) else {
            // A syntactically-valid line whose `kind` this (older) binary does
            // not recognize is a forward-compat skip, not corruption — a newer
            // binary may have written a kind we don't know yet.
            continue;
        };
        out.push(EventRow {
            id: 0,
            ts: parsed.ts,
            kind,
            issue_id: parsed.issue_id,
            worker_uuid: parsed.worker_uuid,
            payload: parsed.payload,
        });
    }
    Ok(out)
}

/// The last `limit` well-formed events from the log at `path`, in file order.
/// A convenience over [`read_all`] for the dashboard's "recent events" view,
/// mirroring [`StateDb::recent_events`] but reading the JSONL mirror.
pub fn tail(path: impl AsRef<Path>, limit: usize) -> Result<Vec<EventRow>, StateError> {
    let mut all = read_all(path)?;
    if all.len() > limit {
        all.drain(0..all.len() - limit);
    }
    Ok(all)
}

// ============================================================================
// emit — the SQLite + JSONL paired writer
// ============================================================================

/// Emit one event to **both** the SQLite `events` table and the `events.jsonl`
/// mirror, keeping the design's "SQLite for query, JSONL for `tail -f`" pair
/// consistent (REQ-14).
///
/// SQLite is the source of truth, so it is written *first*: the row is inserted
/// (minting the autoincrement `id`) and only then is the same event mirrored to
/// the JSONL. The ordering makes the failure modes crash-safe by construction:
/// - if the process dies *between* the two writes, the authoritative SQLite row
///   already exists and the JSONL is merely missing one tail line — a benign
///   under-count in the human-facing mirror, never a phantom event that the
///   authority lacks;
/// - a JSONL write failure is surfaced (the SQLite row is already durable), so
///   the caller learns the mirror diverged rather than silently dropping it.
///
/// Returns the SQLite autoincrement id of the inserted row, matching
/// [`StateDb::append_event`], so a caller that needs the id (e.g. to correlate)
/// still gets it. The `EventKind` taxonomy is the single one from
/// [`crate::state`] — this function does not introduce a parallel vocabulary.
pub fn emit(
    state: &StateDb,
    log: &EventLog,
    kind: EventKind,
    issue_id: Option<&str>,
    worker_uuid: Option<&str>,
    payload: &serde_json::Value,
) -> Result<i64, StateError> {
    // SQLite first: it is the authority and it stamps `ts` + mints `id`, both of
    // which it returns. Mirror the *same* event to the JSONL carrying that exact
    // authoritative `ts` — no re-query, and no second `now()` that could differ
    // by a second and split the two mirrors' timestamps.
    let (id, ts) = state.append_event(kind, issue_id, worker_uuid, payload)?;
    let row = EventRow {
        id,
        ts,
        kind,
        issue_id: issue_id.map(str::to_owned),
        worker_uuid: worker_uuid.map(str::to_owned),
        payload: payload.clone(),
    };
    log.append(&row)?;
    Ok(id)
}

// ============================================================================
// Heartbeat — the reader + staleness check (AC-14)
// ============================================================================

/// The heartbeat filename for a given worker uuid, relative to
/// [`ORCHESTRATOR_DIR`]: `heartbeat-<uuid>.json` (REQ-14 layout).
pub fn heartbeat_file_name(worker_uuid: &str) -> String {
    format!("heartbeat-{worker_uuid}.json")
}

/// A parsed worker heartbeat, `{ts, last_progress, current_op}` (AC-9).
///
/// Workers write this file via a PostToolUse hook (REQ-11); the orchestrator
/// only ever **reads** it — there is no writer here by design. It parses into
/// this typed struct rather than a loose `serde_json::Value` so a malformed
/// heartbeat is rejected at read time instead of flowing into a decision as an
/// untyped blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Worker-reported unix-seconds timestamp of the last hook fire.
    pub ts: i64,
    /// Short description of the most recent progress the worker made.
    pub last_progress: String,
    /// The operation the worker is currently performing.
    pub current_op: String,
}

impl Heartbeat {
    /// Read and parse a worker's heartbeat JSON at `path`.
    ///
    /// # Two heartbeat locations (spec inconsistency)
    ///
    /// The design names the heartbeat file in two places that disagree:
    /// - REQ-11 (and the layout tree) says the worker's PostToolUse hook writes
    ///   `<workspace>/_orchestrator/heartbeat.json` — this worker-written file,
    ///   `mtime`-checked, is what the watchdog polls (see [`heartbeat_is_stale`]);
    /// - REQ-14 lists an orchestrator-side `.orchestrator/heartbeat-<uuid>.json`
    ///   mirror, one per active worker (see [`heartbeat_file_name`]).
    ///
    /// Which of the two the watchdog ultimately consumes is an S4/S1-integration
    /// decision, not settled here. This reader is deliberately **path-agnostic**
    /// so it serves either location unchanged: the caller supplies the path.
    ///
    /// A missing file is [`StateError::Open`] (the caller distinguishes
    /// "no heartbeat yet" from "malformed heartbeat"); malformed JSON — or JSON
    /// missing a required field — is [`StateError::Query`]. Never panics.
    pub fn read(path: impl AsRef<Path>) -> Result<Heartbeat, StateError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(open_err(path))?;
        serde_json::from_str(&content).map_err(query_err("parse heartbeat json"))
    }

    /// Whether the worker-reported [`ts`](Heartbeat::ts) is older than
    /// `threshold_secs` relative to `now` (both unix seconds).
    ///
    /// This is the *content*-based staleness check, keyed on the timestamp the
    /// worker wrote. Per REQ-11 the watchdog (#11 S4) uses the **`mtime`-based**
    /// check ([`heartbeat_is_stale`], "not parsed for content, just
    /// `mtime`-checked") — *not* this one; this method is offered only for
    /// callers that deliberately trust the worker's self-reported clock.
    ///
    /// The comparison is `age > threshold_secs` (strictly older), matching
    /// [`heartbeat_is_stale`] exactly so the two checks agree at the boundary: a
    /// heartbeat exactly `threshold_secs` old is *fresh* in both.
    ///
    /// A `ts` in the future (clock skew) is treated as fresh: `now - self.ts`
    /// goes negative, and the `age >= 0` guard short-circuits to `false` before
    /// the `u64` cast — it does not saturate at 0.
    pub fn is_stale(&self, now: i64, threshold_secs: u64) -> bool {
        let age = now - self.ts;
        age >= 0 && (age as u64) > threshold_secs
    }
}

/// Whether the heartbeat file at `path` is stale by its **mtime** — the
/// authoritative watchdog check per the design (REQ-11: the heartbeat is
/// "not parsed for content, just `mtime`-checked").
///
/// Returns `true` when the file's last-modified time is more than `threshold`
/// in the past relative to now. This is what the future watchdog (#11 S4) uses:
/// the PostToolUse hook rewrites the file every ~10s, so a file whose mtime has
/// not advanced past the threshold means the worker's hook has stopped firing.
///
/// A **missing** file counts as stale (`Ok(true)`): a worker that never wrote a
/// heartbeat, or whose file vanished, is exactly the "no liveness signal" case
/// the watchdog must act on. A file whose mtime is in the future (clock skew)
/// is treated as fresh. Any other I/O error is surfaced.
pub fn heartbeat_is_stale(path: impl AsRef<Path>, threshold: Duration) -> Result<bool, StateError> {
    let path = path.as_ref();
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(source) => return Err(open_err(path)(source)),
    };
    let mtime = meta.modified().map_err(open_err(path))?;
    // Age from mtime to now. A future mtime (skew) yields an Err from
    // `elapsed()`, which we read as "not stale" — never punish a worker for a
    // clock running slightly ahead.
    match mtime.elapsed() {
        Ok(age) => Ok(age > threshold),
        Err(_) => Ok(false),
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Wrap an error into [`StateError::Open`] for a given path — the log and
/// heartbeat files live under `.orchestrator/` alongside `state.db`, so an
/// open/read failure reuses the state layer's open-error variant for a uniform
/// diagnostic surface.
fn open_err<E>(path: &Path) -> impl Fn(E) -> StateError + '_
where
    E: std::error::Error + Send + Sync + 'static,
{
    move |e| StateError::Open {
        path: path.to_path_buf(),
        source: Box::new(e),
    }
}

/// Build a [`StateError::Query`] reporting an unparseable interior line at a
/// 1-based line number in `events.jsonl` — the signal the reconciler acts on.
fn corrupt_line_err(path: &Path, line_no: usize) -> StateError {
    StateError::Query {
        context: format!(
            "{} is corrupted at line {line_no} (unparseable interior line)",
            path.display()
        ),
        source: format!("interior line {line_no} does not parse as an event").into(),
    }
}

/// Wrap an I/O write failure into [`StateError::Query`] naming the log path.
fn write_err(path: &Path) -> impl Fn(std::io::Error) -> StateError + '_ {
    move |e| StateError::Query {
        context: format!("append to {}", path.display()),
        source: Box::new(e),
    }
}

/// Wrap a serialization / parse error into [`StateError::Query`].
fn query_err<E>(context: &'static str) -> impl Fn(E) -> StateError
where
    E: std::error::Error + Send + Sync + 'static,
{
    move |e| StateError::Query {
        context: context.to_string(),
        source: Box::new(e),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    /// A tempdir plus an `EventLog` opened under it (as `.orchestrator/`).
    fn temp_log() -> (TempDir, EventLog) {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = EventLog::open(dir.path().join(ORCHESTRATOR_DIR)).expect("open events.jsonl");
        (dir, log)
    }

    /// A representative event row; `id` is irrelevant to the JSONL projection.
    fn row(kind: EventKind, issue: Option<&str>, ts: i64) -> EventRow {
        EventRow {
            id: 0,
            ts,
            kind,
            issue_id: issue.map(str::to_owned),
            worker_uuid: None,
            payload: serde_json::json!({"from_phase": "graphed", "to_phase": "implementing"}),
        }
    }

    #[test]
    fn append_n_events_yields_n_valid_json_lines() {
        let (_dir, log) = temp_log();
        for i in 0..5 {
            log.append(&row(EventKind::Transition, Some("#1"), i))
                .expect("append");
        }
        let content = std::fs::read_to_string(log.path()).expect("read back");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5, "one line per append");
        for (i, line) in lines.iter().enumerate() {
            let parsed: EventLine = serde_json::from_str(line).expect("each line is valid JSON");
            assert_eq!(parsed.ts, i as i64);
            assert_eq!(parsed.kind, "transition");
            assert_eq!(parsed.issue_id.as_deref(), Some("#1"));
            assert_eq!(parsed.payload["to_phase"], "implementing");
        }
    }

    #[test]
    fn appended_line_has_no_sqlite_id_field() {
        // The JSONL wire shape mirrors EventRow MINUS the SQLite `id`.
        let (_dir, log) = temp_log();
        let mut r = row(EventKind::Spawn, Some("#7"), 42);
        r.id = 999; // must not appear in the line.
        log.append(&r).expect("append");
        let content = std::fs::read_to_string(log.path()).expect("read");
        let value: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert!(value.get("id").is_none(), "id must not be serialized");
        assert_eq!(value["kind"], "spawn");
    }

    #[test]
    fn reopening_appends_and_preserves_prior_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(ORCHESTRATOR_DIR).join(EVENTS_FILE);
        {
            let log = EventLog::open_file(&path).expect("open 1");
            log.append(&row(EventKind::Spawn, Some("#1"), 1)).unwrap();
            log.append(&row(EventKind::Transition, Some("#1"), 2))
                .unwrap();
        }
        // Reopen — append mode must NOT truncate.
        {
            let log = EventLog::open_file(&path).expect("open 2");
            log.append(&row(EventKind::QaResult, Some("#1"), 3))
                .unwrap();
        }
        let events = read_all(&path).expect("read all");
        assert_eq!(events.len(), 3, "prior lines survive a reopen");
        assert_eq!(events[0].kind, EventKind::Spawn);
        assert_eq!(events[1].kind, EventKind::Transition);
        assert_eq!(events[2].kind, EventKind::QaResult);
        assert_eq!(events[2].ts, 3);
    }

    #[test]
    fn partial_trailing_line_does_not_break_a_line_reader() {
        let (_dir, log) = temp_log();
        log.append(&row(EventKind::Spawn, Some("#1"), 1)).unwrap();
        log.append(&row(EventKind::Transition, Some("#1"), 2))
            .unwrap();
        // Simulate a crash mid-write: a torn JSON fragment with no newline.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(log.path())
                .expect("reopen for torn append");
            f.write_all(br#"{"ts":3,"kind":"qa_res"#)
                .expect("write torn tail");
        }
        // The two whole lines survive; the torn tail is skipped, not fatal.
        let events = read_all(log.path()).expect("torn tail must not error");
        assert_eq!(events.len(), 2, "torn trailing line is skipped");
        assert_eq!(events[1].kind, EventKind::Transition);
    }

    #[test]
    fn interior_corrupt_line_is_surfaced_not_dropped() {
        // The reader tolerates only a torn *trailing* line. An unparseable
        // *interior* line is real corruption and must be surfaced (naming the
        // 1-based line number) so the reconciler can rebuild from SQLite —
        // silently dropping it would under-count the mirror with no signal.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(EVENTS_FILE);
        let body = concat!(
            r#"{"ts":1,"kind":"spawn","payload":{}}"#,
            "\n",
            "{ this is not valid json\n", // interior corruption, line 2
            r#"{"ts":3,"kind":"transition","payload":{}}"#,
            "\n",
        );
        std::fs::write(&path, body).unwrap();
        let err = read_all(&path).expect_err("interior corruption must surface");
        match err {
            StateError::Query { context, .. } => {
                assert!(
                    context.contains("line 2"),
                    "names the corrupt line: {context}"
                );
            }
            other => panic!("expected StateError::Query, got {other:?}"),
        }
    }

    #[test]
    fn read_all_skips_blank_and_unknown_kind_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(EVENTS_FILE);
        // Blank line, a good line, then a syntactically-valid line with a kind
        // this binary doesn't know (a future-binary write) — both skipped.
        let body = concat!(
            "\n",
            r#"{"ts":1,"kind":"spawn","payload":{}}"#,
            "\n",
            r#"{"ts":2,"kind":"time_travel","payload":{}}"#,
            "\n",
        );
        std::fs::write(&path, body).unwrap();
        let events = read_all(&path).expect("read");
        assert_eq!(events.len(), 1, "blank + unknown-kind lines skipped");
        assert_eq!(events[0].kind, EventKind::Spawn);
    }

    #[test]
    fn read_all_of_missing_file_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let events = read_all(dir.path().join("nope.jsonl")).expect("missing = empty");
        assert!(events.is_empty());
    }

    #[test]
    fn tail_returns_the_last_n_in_order() {
        let (_dir, log) = temp_log();
        for i in 0..6 {
            log.append(&row(EventKind::Transition, Some("#1"), i))
                .unwrap();
        }
        let last3 = tail(log.path(), 3).expect("tail");
        assert_eq!(last3.len(), 3);
        assert_eq!(last3[0].ts, 3);
        assert_eq!(last3[2].ts, 5);
        // A limit past the length returns everything.
        assert_eq!(tail(log.path(), 100).expect("tail").len(), 6);
    }

    // --- emit (SQLite + JSONL pairing) --------------------------------------

    #[test]
    fn emit_writes_both_sqlite_and_jsonl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let orch = dir.path().join(ORCHESTRATOR_DIR);
        let state = StateDb::open(orch.join("state.db")).expect("state.db");
        let log = EventLog::open(&orch).expect("events.jsonl");

        let payload = serde_json::json!({"from_phase": "graphed", "to_phase": "implementing"});
        let id = emit(
            &state,
            &log,
            EventKind::Transition,
            Some("#42"),
            None,
            &payload,
        )
        .expect("emit");
        assert!(id > 0, "SQLite mints a positive autoincrement id");

        // SQLite side.
        let db_events = state.recent_events(10).expect("recent");
        assert_eq!(db_events.len(), 1);
        assert_eq!(db_events[0].kind, EventKind::Transition);
        assert_eq!(db_events[0].issue_id.as_deref(), Some("#42"));

        // JSONL mirror side — same kind, issue, payload, and the exact ts.
        let jsonl = read_all(log.path()).expect("read jsonl");
        assert_eq!(jsonl.len(), 1);
        assert_eq!(jsonl[0].kind, EventKind::Transition);
        assert_eq!(jsonl[0].issue_id.as_deref(), Some("#42"));
        assert_eq!(jsonl[0].payload["to_phase"], "implementing");
        assert_eq!(
            jsonl[0].ts, db_events[0].ts,
            "mirror carries the authority's timestamp"
        );
    }

    // --- reconciler (rebuild_from) ------------------------------------------

    #[test]
    fn rebuild_from_reconstructs_jsonl_from_sqlite_exactly_and_in_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let orch = dir.path().join(ORCHESTRATOR_DIR);
        let state = StateDb::open(orch.join("state.db")).expect("state.db");
        let log = EventLog::open(&orch).expect("events.jsonl");

        // Emit several events the normal way — both mirrors agree.
        let kinds = [
            EventKind::Spawn,
            EventKind::Transition,
            EventKind::QaResult,
            EventKind::Convergence,
        ];
        for (i, kind) in kinds.iter().enumerate() {
            emit(
                &state,
                &log,
                *kind,
                Some(&format!("#{i}")),
                None,
                &serde_json::json!({"n": i}),
            )
            .expect("emit");
        }

        // Desync the JSONL: drop its tail and append an unrelated bogus line, so
        // the mirror no longer matches SQLite (a torn/desynced mirror).
        {
            let all = read_all(log.path()).expect("read jsonl");
            assert_eq!(all.len(), 4, "precondition: mirror has all 4");
            // Rewrite the file with only the first two lines + one garbage line.
            let mut corrupted = String::new();
            for ev in &all[..2] {
                corrupted.push_str(&serde_json::to_string(&EventLine::from_row(ev)).unwrap());
                corrupted.push('\n');
            }
            corrupted.push_str("{bogus not json}\n");
            std::fs::write(log.path(), corrupted).unwrap();
        }
        drop(log); // release the desynced handle before rebuilding.

        // Rebuild from the authority.
        let rebuilt = EventLog::rebuild_from(&state, &orch).expect("rebuild");

        // The JSONL now matches the SQLite events exactly and in order.
        let sqlite = state.all_events().expect("all_events");
        let jsonl = read_all(rebuilt.path()).expect("read rebuilt jsonl");
        assert_eq!(jsonl.len(), sqlite.len(), "same count as authority");
        for (db_ev, file_ev) in sqlite.iter().zip(jsonl.iter()) {
            // `id` differs by design (JSONL carries none, read back as 0), but
            // every observable field must match, in order.
            assert_eq!(file_ev.ts, db_ev.ts);
            assert_eq!(file_ev.kind, db_ev.kind);
            assert_eq!(file_ev.issue_id, db_ev.issue_id);
            assert_eq!(file_ev.worker_uuid, db_ev.worker_uuid);
            assert_eq!(file_ev.payload, db_ev.payload);
        }

        // The returned handle is a normal append-only one: appending works and
        // lands after the rebuilt lines.
        rebuilt
            .append(&row(EventKind::WatchdogKill, Some("#late"), 999))
            .expect("append after rebuild");
        let after = read_all(rebuilt.path()).expect("read after append");
        assert_eq!(after.len(), sqlite.len() + 1);
        assert_eq!(after.last().unwrap().kind, EventKind::WatchdogKill);
    }

    #[test]
    fn rebuild_from_on_missing_jsonl_writes_full_stream() {
        // No JSONL on disk at all (e.g. it was never created / was deleted):
        // rebuild materializes the whole authoritative stream from scratch.
        let dir = tempfile::tempdir().expect("tempdir");
        let orch = dir.path().join(ORCHESTRATOR_DIR);
        let state = StateDb::open(orch.join("state.db")).expect("state.db");
        for i in 0..3 {
            state
                .append_event(
                    EventKind::Spawn,
                    Some(&format!("#{i}")),
                    None,
                    &serde_json::json!({}),
                )
                .unwrap();
        }
        assert!(
            !orch.join(EVENTS_FILE).exists(),
            "precondition: no events.jsonl yet"
        );
        let log = EventLog::rebuild_from(&state, &orch).expect("rebuild from scratch");
        assert_eq!(read_all(log.path()).expect("read").len(), 3);
    }

    // --- heartbeat ----------------------------------------------------------

    #[test]
    fn heartbeat_file_name_matches_layout() {
        assert_eq!(heartbeat_file_name("abcd-1234"), "heartbeat-abcd-1234.json");
    }

    #[test]
    fn heartbeat_reads_valid_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(heartbeat_file_name("w1"));
        std::fs::write(
            &path,
            r#"{"ts":1000,"last_progress":"edited lib.rs","current_op":"cargo test"}"#,
        )
        .unwrap();
        let hb = Heartbeat::read(&path).expect("valid heartbeat parses");
        assert_eq!(hb.ts, 1000);
        assert_eq!(hb.last_progress, "edited lib.rs");
        assert_eq!(hb.current_op, "cargo test");
    }

    #[test]
    fn heartbeat_rejects_malformed_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hb.json");
        // Missing the required `current_op` field.
        std::fs::write(&path, r#"{"ts":1,"last_progress":"x"}"#).unwrap();
        let err = Heartbeat::read(&path).unwrap_err();
        assert!(matches!(err, StateError::Query { .. }));
        // Outright garbage.
        std::fs::write(&path, "not json at all").unwrap();
        assert!(matches!(
            Heartbeat::read(&path).unwrap_err(),
            StateError::Query { .. }
        ));
    }

    #[test]
    fn heartbeat_missing_file_is_open_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = Heartbeat::read(dir.path().join("absent.json")).unwrap_err();
        assert!(matches!(err, StateError::Open { .. }));
    }

    #[test]
    fn is_stale_around_the_threshold() {
        let hb = Heartbeat {
            ts: 1000,
            last_progress: "x".into(),
            current_op: "y".into(),
        };
        // `age > threshold` (matches heartbeat_is_stale): 119 fresh, 120 (==
        // threshold) fresh, 121 stale.
        assert!(!hb.is_stale(1119, 120), "119s old is under threshold");
        assert!(
            !hb.is_stale(1120, 120),
            "exactly at threshold is fresh (age > threshold, agreeing with the mtime check)"
        );
        assert!(hb.is_stale(1121, 120), "strictly past threshold is stale");
        // A ts in the future (skew) is never stale.
        assert!(!hb.is_stale(900, 120));
    }

    #[test]
    fn mtime_staleness_true_and_false_around_threshold() {
        use std::time::{Duration, SystemTime};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("heartbeat-w.json");
        std::fs::write(&path, r#"{"ts":0,"last_progress":"","current_op":""}"#).unwrap();

        // Freshly written: not stale under any positive threshold.
        assert!(!heartbeat_is_stale(&path, Duration::from_secs(60)).expect("fresh"));

        // Backdate the mtime well past the threshold → stale.
        let old = SystemTime::now() - Duration::from_secs(300);
        let old = filetime_set(&path, old);
        assert!(old, "set mtime supported on this platform");
        assert!(
            heartbeat_is_stale(&path, Duration::from_secs(120)).expect("stale"),
            "a 300s-old heartbeat is stale past a 120s threshold"
        );
        assert!(
            !heartbeat_is_stale(&path, Duration::from_secs(600)).expect("fresh"),
            "the same file is fresh under a 600s threshold"
        );
    }

    #[test]
    fn mtime_staleness_missing_file_is_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            heartbeat_is_stale(dir.path().join("gone.json"), Duration::from_secs(1)).expect("ok"),
            "a missing heartbeat is stale (no liveness signal)"
        );
    }

    /// Backdate a file's mtime using `filetime`-free std: set both atime/mtime
    /// via a second write is not enough (mtime tracks the write), so we use
    /// `std::fs::File::set_modified`, available since Rust 1.75.
    fn filetime_set(path: &Path, when: std::time::SystemTime) -> bool {
        let f = OpenOptions::new().write(true).open(path).expect("open");
        f.set_modified(when).is_ok()
    }
}

// ============================================================================
// Property-based tests
// ============================================================================

#[cfg(test)]
mod proptests {
    use super::*;

    use proptest::prelude::*;
    use tempfile::TempDir;

    /// One arbitrary event's ingredients. `kind` is drawn from the real
    /// [`EventKind`] set; the optional ids avoid characters that don't
    /// round-trip through JSON strings trivially (the payload is arbitrary JSON,
    /// exercised separately).
    #[derive(Debug, Clone)]
    struct ArbEvent {
        kind: EventKind,
        ts: i64,
        issue_id: Option<String>,
        worker_uuid: Option<String>,
        payload: serde_json::Value,
    }

    fn arb_kind() -> impl Strategy<Value = EventKind> {
        prop_oneof![
            Just(EventKind::Spawn),
            Just(EventKind::Transition),
            Just(EventKind::QaResult),
            Just(EventKind::WatchdogKill),
            Just(EventKind::Convergence),
        ]
    }

    prop_compose! {
        fn arb_event()(
            kind in arb_kind(),
            ts in any::<i64>(),
            issue_id in prop::option::of("[a-zA-Z0-9#_-]{1,12}"),
            worker_uuid in prop::option::of("[a-f0-9-]{1,36}"),
            // A small, JSON-safe payload: string keys → string/number values.
            payload in prop::collection::hash_map(
                "[a-z_]{1,8}",
                prop_oneof![
                    "[a-zA-Z0-9 ]{0,20}".prop_map(serde_json::Value::from),
                    any::<i64>().prop_map(serde_json::Value::from),
                ],
                0..4,
            ),
        ) -> ArbEvent {
            ArbEvent {
                kind,
                ts,
                issue_id,
                worker_uuid,
                payload: serde_json::Value::Object(payload.into_iter().collect()),
            }
        }
    }

    proptest! {
        /// Appending an arbitrary sequence of events yields a file whose lines
        /// each parse back to the original event, in order (round-trip +
        /// append-only ordering preserved). This is the core append-log
        /// contract: nothing is dropped, reordered, or mutated.
        #[test]
        fn append_sequence_round_trips_in_order(events in prop::collection::vec(arb_event(), 0..30)) {
            let dir = TempDir::new().expect("tempdir");
            let log = EventLog::open_file(dir.path().join(EVENTS_FILE)).expect("open");

            for e in &events {
                log.append(&EventRow {
                    id: 0,
                    ts: e.ts,
                    kind: e.kind,
                    issue_id: e.issue_id.clone(),
                    worker_uuid: e.worker_uuid.clone(),
                    payload: e.payload.clone(),
                })
                .expect("append");
            }

            let read = read_all(log.path()).expect("read back");
            prop_assert_eq!(read.len(), events.len());
            for (orig, got) in events.iter().zip(read.iter()) {
                prop_assert_eq!(got.kind, orig.kind);
                prop_assert_eq!(got.ts, orig.ts);
                prop_assert_eq!(&got.issue_id, &orig.issue_id);
                prop_assert_eq!(&got.worker_uuid, &orig.worker_uuid);
                prop_assert_eq!(&got.payload, &orig.payload);
            }
        }

        /// Re-opening the log mid-sequence (a process restart) must not truncate:
        /// splitting the appends across two `EventLog` handles yields the same
        /// full, in-order file as doing them in one handle.
        #[test]
        fn reopen_preserves_all_prior_lines(
            events in prop::collection::vec(arb_event(), 1..20),
            split in 0usize..20,
        ) {
            let dir = TempDir::new().expect("tempdir");
            let path = dir.path().join(EVENTS_FILE);
            let cut = split.min(events.len());

            let write = |log: &EventLog, slice: &[ArbEvent]| {
                for e in slice {
                    log.append(&EventRow {
                        id: 0,
                        ts: e.ts,
                        kind: e.kind,
                        issue_id: e.issue_id.clone(),
                        worker_uuid: e.worker_uuid.clone(),
                        payload: e.payload.clone(),
                    })
                    .expect("append");
                }
            };

            {
                let log = EventLog::open_file(&path).expect("open 1");
                write(&log, &events[..cut]);
            }
            {
                let log = EventLog::open_file(&path).expect("open 2");
                write(&log, &events[cut..]);
            }

            let read = read_all(&path).expect("read back");
            prop_assert_eq!(read.len(), events.len(), "reopen must not truncate");
            for (orig, got) in events.iter().zip(read.iter()) {
                prop_assert_eq!(got.ts, orig.ts);
                prop_assert_eq!(got.kind, orig.kind);
            }
        }
    }
}
