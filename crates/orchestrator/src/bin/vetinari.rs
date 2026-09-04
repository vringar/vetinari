//! `vetinari` — the read-only introspection CLI for the VDD orchestrator
//! (`.design/swarm-kickoff-spec.md` §2.2). This is the section chief's
//! introspection surface: the one command that joins the orchestrator's private
//! execution state (`state.db` + `events.jsonl`) with crosslink's dependency
//! DAG into a single "what is my node doing / what is blocked on what" view.
//!
//! # Read-only is the whole invariant
//!
//! This binary NEVER writes `state.db` and NEVER writes crosslink. Every write
//! to orchestrator state stays through the pump, and every write to crosslink
//! stays through `crosslink`/`crosslink_api`, so the single-writer property
//! (REQ-3) holds and the chief can never corrupt orchestrator state. The
//! guarantee is structural, not conventional:
//!
//! - `state.db` is opened through [`StateDb::open_read_only`], which uses
//!   `SQLITE_OPEN_READ_ONLY` (SQLite itself refuses any write or DDL) and sets a
//!   `busy_timeout` so a transient WAL lock from the *running* pump is waited
//!   out rather than surfaced as an error — a second reader must never block the
//!   single writer. It runs no migration, so a schema mismatch degrades to a
//!   clear error, never a rewrite.
//! - crosslink is read only through `crosslink_api`'s read methods
//!   ([`CrosslinkRepo::open_blockers`], [`CrosslinkRepo::list_by_label`]); no
//!   label is ever written here.
//!
//! # No shell-out (AC-24)
//!
//! Every fact comes from the Rust APIs (`rusqlite` via `StateDb`, `crosslink_api`
//! for the DAG). Nothing here constructs a `std::process::Command` — the xtask
//! lint scans `src/bin/` and must stay clean.
//!
//! # Subcommands
//!
//! ```text
//! vetinari status [--issue N]            phase / substate / round / streaks / landing-retry
//! vetinari graph                         each issue's crosslink open-blockers × its state.db phase
//! vetinari workers                       active workers: role, round, workspace, pid, heartbeat age
//! vetinari events [--issue N] [--tail K]  recent events (spawn / transition / qa_result / …)
//! vetinari crossbridge                   inbound/outbound xb issues (integration not yet active)
//! ```
//!
//! Each subcommand prints a human-readable table by default and structured JSON
//! under `--json`. `--orchestrator-dir PATH` overrides the default discovery of
//! the `.orchestrator/` directory (which walks up from the current directory).

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};

use miette::{bail, miette, IntoDiagnostic, Result, WrapErr};
use serde_json::{json, Value};
use vetinari_crosslink_api::{CrosslinkRepo, IssueInfo};

use orchestrator::events::ORCHESTRATOR_DIR;
use orchestrator::state::{ActiveWorkerRow, EventRow, IssueRow, StateDb};

/// The crosslink label a graphed, pump-pickable issue carries — the DAG the
/// `graph` view enumerates over (mirrors `pump.rs` `GRAPHED_LABEL`).
const GRAPHED_LABEL: &str = "phase:graphed";

/// crossbridge marker labels. crossbridge ingestion is NOT built yet (a later
/// step of the swarm-kickoff spec, §1.2); these are the labels an embedded
/// server *will* stamp on the inbound/outbound issues it creates, and which the
/// `crossbridge` view reads today from whatever is already present. When the
/// `crossbridge_api` crate lands it will own these (`crossbridge_api::labels::*`)
/// and this binary should re-export from there rather than redefine them.
const XB_INBOUND_LABEL: &str = "xb:inbound";
/// See [`XB_INBOUND_LABEL`].
const XB_OUTBOUND_LABEL: &str = "xb:outbound";
/// Prefix of the `xb-source:<peer-slug>` label recording the submitting peer.
const XB_SOURCE_PREFIX: &str = "xb-source:";
/// Prefix of the `xb-status:<state>` courtesy label (authority is `state.db`,
/// never this label — review B5).
const XB_STATUS_PREFIX: &str = "xb-status:";
/// Prefix of the `xb-ref:<id>` label correlating an inbound issue to its
/// source-side request.
const XB_REF_PREFIX: &str = "xb-ref:";

/// Heartbeat-age threshold (seconds) beyond which the `workers` view flags a
/// worker as `stale`. Mirrors the default `worker_timeout_secs` (config.rs): a
/// worker whose hook has not written a heartbeat within this window is the
/// "no liveness signal" case the watchdog acts on. Advisory only — this
/// read-only view reports it, it does not kill anything.
const STALE_THRESHOLD_SECS: i64 = 120;

/// Default number of events shown by `events` when `--tail` is not given.
const DEFAULT_EVENT_TAIL: usize = 20;

fn main() -> Result<()> {
    let args = Cli::parse(std::env::args().skip(1))?;
    match args.command {
        Command::Status => cmd_status(&args),
        Command::Graph => cmd_graph(&args),
        Command::Workers => cmd_workers(&args),
        Command::Events => cmd_events(&args),
        Command::Crossbridge => cmd_crossbridge(&args),
    }
}

// ============================================================================
// Argument parsing (hand-rolled — clap is not a dependency of this crate)
// ============================================================================

/// The five read-only subcommands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Status,
    Graph,
    Workers,
    Events,
    Crossbridge,
}

/// Parsed command line.
#[derive(Debug)]
struct Cli {
    command: Command,
    /// Override for the `.orchestrator/` directory; discovered from the cwd when
    /// absent.
    orchestrator_dir: Option<PathBuf>,
    /// Emit structured JSON instead of a human-readable table.
    json: bool,
    /// Restrict to one crosslink issue id (`status`, `events`).
    issue: Option<i64>,
    /// Number of trailing events to show (`events`).
    tail: Option<usize>,
}

impl Cli {
    /// Parse the argument iterator (already stripped of `argv[0]`).
    ///
    /// Deliberately minimal — five subcommands and four flags do not warrant a
    /// parser dependency. Unknown flags and missing values are rejected with a
    /// diagnostic rather than silently ignored.
    fn parse(args: impl Iterator<Item = String>) -> Result<Cli> {
        let mut command: Option<Command> = None;
        let mut orchestrator_dir = None;
        let mut json = false;
        let mut issue = None;
        let mut tail = None;

        let mut it = args.peekable();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                "--json" => json = true,
                "--orchestrator-dir" => {
                    let v = it
                        .next()
                        .ok_or_else(|| miette!("`--orchestrator-dir` requires a path argument"))?;
                    orchestrator_dir = Some(PathBuf::from(v));
                }
                "--issue" => {
                    let v = it
                        .next()
                        .ok_or_else(|| miette!("`--issue` requires an issue-id argument"))?;
                    issue =
                        Some(v.trim_start_matches('#').parse::<i64>().map_err(|e| {
                            miette!("`--issue` value `{v}` is not an integer: {e}")
                        })?);
                }
                "--tail" => {
                    let v = it
                        .next()
                        .ok_or_else(|| miette!("`--tail` requires a count argument"))?;
                    tail = Some(
                        v.parse::<usize>()
                            .map_err(|e| miette!("`--tail` value `{v}` is not a count: {e}"))?,
                    );
                }
                other if other.starts_with('-') => {
                    bail!("unknown flag `{other}`\n\n{USAGE}");
                }
                other => {
                    if command.is_some() {
                        bail!("unexpected extra argument `{other}`\n\n{USAGE}");
                    }
                    command = Some(match other {
                        "status" => Command::Status,
                        "graph" => Command::Graph,
                        "workers" => Command::Workers,
                        "events" => Command::Events,
                        "crossbridge" => Command::Crossbridge,
                        _ => bail!("unknown subcommand `{other}`\n\n{USAGE}"),
                    });
                }
            }
        }

        let command = command.ok_or_else(|| miette!("no subcommand given\n\n{USAGE}"))?;
        Ok(Cli {
            command,
            orchestrator_dir,
            json,
            issue,
            tail,
        })
    }
}

/// Usage text for `--help` and argument errors.
const USAGE: &str = "\
vetinari — read-only introspection for the VDD orchestrator

USAGE:
    vetinari [--orchestrator-dir PATH] <SUBCOMMAND> [FLAGS]

SUBCOMMANDS:
    status [--issue N]            phase, substate, round, empty-round streak, landing retry
    graph                        each issue's open blockers joined with its execution phase
    workers                      active workers: role, round, workspace, pid, heartbeat age
    events [--issue N] [--tail K]  recent events (default K = 20)
    crossbridge                  inbound/outbound crossbridge issues (integration not yet active)

FLAGS:
    --json                 emit structured JSON instead of a table
    --orchestrator-dir P   use P as the .orchestrator/ directory (default: discover from cwd)
    -h, --help             print this help
";

// ============================================================================
// status
// ============================================================================

/// `vetinari status [--issue N]` — the persisted phase machine of one or every
/// tracked issue, read straight from the `issues` table.
fn cmd_status(args: &Cli) -> Result<()> {
    let dir = resolve_orchestrator_dir(args.orchestrator_dir.as_deref())?;
    let state = open_state(&dir)?;

    let rows = match args.issue {
        Some(id) => match state.get_issue(&id.to_string()).into_diagnostic()? {
            Some(row) => vec![row],
            None => {
                if args.json {
                    return write_json(&json!({"issue": id.to_string(), "tracked": false}));
                }
                return write_out(&format!(
                    "issue #{id} is not tracked in state.db (never picked up, or a different id form)\n"
                ));
            }
        },
        None => state.list_issues().into_diagnostic()?,
    };

    if args.json {
        let arr: Vec<Value> = rows.iter().map(issue_row_json).collect();
        return write_json(&Value::Array(arr));
    }

    if rows.is_empty() {
        return write_out("no issues tracked in state.db yet\n");
    }
    let table = render_table(
        &[
            "ISSUE",
            "PHASE",
            "SUBSTATE",
            "ROUND",
            "EMPTY_STREAK",
            "LANDING_RETRY",
            "CONVERGENCE",
        ],
        &rows
            .iter()
            .map(|r| {
                vec![
                    format!("#{}", r.issue_id),
                    r.phase.to_string(),
                    r.phase_substate.clone().unwrap_or_else(|| "-".to_string()),
                    r.round.to_string(),
                    r.empty_round_streak.to_string(),
                    r.landing_retry_count.to_string(),
                    r.convergence_mode.to_string(),
                ]
            })
            .collect::<Vec<_>>(),
    );
    write_out(&table)
}

/// The full JSON projection of an [`IssueRow`] (the struct derives no
/// `Serialize`, and this binary must not change that, so the shape is built by
/// hand — enums are rendered as their canonical `state.db` tokens).
fn issue_row_json(r: &IssueRow) -> Value {
    json!({
        "issue_id": r.issue_id,
        "phase": r.phase.to_string(),
        "phase_substate": r.phase_substate,
        "round": r.round,
        "convergence_mode": r.convergence_mode.to_string(),
        "empty_round_streak": r.empty_round_streak,
        "last_diff_hash": r.last_diff_hash,
        "landing_retry_count": r.landing_retry_count,
        "updated_at": r.updated_at,
    })
}

// ============================================================================
// graph
// ============================================================================

/// `vetinari graph` — the genuinely new synthesis (§2.2): for every issue the
/// node knows about, its crosslink **open blockers** joined with each issue's
/// **execution phase** from `state.db`. `just graph` shows crosslink
/// ready/blocked but is blind to phase; this is the first execution-phase-aware
/// "what is blocked on what" view of the node.
///
/// The id set is the union of (a) every issue tracked in `state.db` and (b)
/// every open `phase:graphed` issue in crosslink — so a graphed issue still held
/// by an open blocker (which the pump has not yet seeded into `state.db`) is
/// still shown. For each id the open-blocker edge set comes from crosslink and
/// each node's phase (the issue's and each blocker's) comes from `state.db`,
/// rendered `untracked` when no `state.db` row exists yet.
fn cmd_graph(args: &Cli) -> Result<()> {
    let dir = resolve_orchestrator_dir(args.orchestrator_dir.as_deref())?;
    let state = open_state(&dir)?;
    let crosslink = open_crosslink(&dir)?;

    // state.db phase, keyed by crosslink id (state.db issue_id == the crosslink
    // id in decimal, per pump.rs ingest).
    let issues = state.list_issues().into_diagnostic()?;
    let mut phase_of: std::collections::BTreeMap<i64, String> = std::collections::BTreeMap::new();
    for row in &issues {
        if let Ok(id) = row.issue_id.parse::<i64>() {
            phase_of.insert(id, row.phase.to_string());
        }
    }

    // Union of state.db ids and crosslink graphed-open issue ids.
    let graphed = crosslink
        .list_by_label("open", GRAPHED_LABEL)
        .into_diagnostic()
        .wrap_err("list `open` issues labeled `phase:graphed`")?;
    let mut ids: std::collections::BTreeSet<i64> = phase_of.keys().copied().collect();
    ids.extend(graphed.iter().map(|i| i.id));

    let mut nodes: Vec<Value> = Vec::new();
    let mut table_rows: Vec<Vec<String>> = Vec::new();
    for id in &ids {
        let blockers = crosslink
            .open_blockers(*id)
            .into_diagnostic()
            .wrap_err_with(|| format!("read open blockers of issue #{id}"))?;
        let phase = phase_of
            .get(id)
            .cloned()
            .unwrap_or_else(|| "untracked".to_string());

        let blocker_json: Vec<Value> = blockers
            .iter()
            .map(|b| {
                json!({
                    "id": b,
                    "phase": phase_of.get(b).cloned().unwrap_or_else(|| "untracked".to_string()),
                })
            })
            .collect();
        nodes.push(json!({
            "issue": id,
            "phase": phase,
            "ready": blockers.is_empty(),
            "open_blockers": blocker_json,
        }));

        let blocked_by = if blockers.is_empty() {
            "ready".to_string()
        } else {
            blockers
                .iter()
                .map(|b| {
                    format!(
                        "#{b}({})",
                        phase_of
                            .get(b)
                            .cloned()
                            .unwrap_or_else(|| "untracked".to_string())
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        table_rows.push(vec![format!("#{id}"), phase, blocked_by]);
    }

    if args.json {
        return write_json(&Value::Array(nodes));
    }
    if table_rows.is_empty() {
        return write_out("no graphed issues and no tracked issues\n");
    }
    write_out(&render_table(
        &["ISSUE", "PHASE", "BLOCKED_BY"],
        &table_rows,
    ))
}

// ============================================================================
// workers
// ============================================================================

/// `vetinari workers` — one row per live worker from the `active_workers` table,
/// with a computed heartbeat age and staleness flag.
fn cmd_workers(args: &Cli) -> Result<()> {
    let dir = resolve_orchestrator_dir(args.orchestrator_dir.as_deref())?;
    let state = open_state(&dir)?;
    let workers = state.list_active_workers().into_diagnostic()?;
    let now = now_unix();

    if args.json {
        let arr: Vec<Value> = workers.iter().map(|w| worker_json(w, now)).collect();
        return write_json(&Value::Array(arr));
    }
    if workers.is_empty() {
        return write_out("no active workers\n");
    }
    let rows: Vec<Vec<String>> = workers
        .iter()
        .map(|w| {
            let age = heartbeat_age(w, now);
            vec![
                short_uuid(&w.worker_uuid),
                format!("#{}", w.issue_id),
                w.role.to_string(),
                w.round.to_string(),
                w.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                format!(
                    "{age}s{}",
                    if age > STALE_THRESHOLD_SECS {
                        " STALE"
                    } else {
                        ""
                    }
                ),
                w.workspace_path.display().to_string(),
            ]
        })
        .collect();
    write_out(&render_table(
        &[
            "WORKER",
            "ISSUE",
            "ROLE",
            "ROUND",
            "PID",
            "HEARTBEAT",
            "WORKSPACE",
        ],
        &rows,
    ))
}

/// Heartbeat age in seconds (clamped at 0 for a future timestamp / clock skew).
fn heartbeat_age(w: &ActiveWorkerRow, now: i64) -> i64 {
    (now - w.last_heartbeat).max(0)
}

/// The full JSON projection of an [`ActiveWorkerRow`] plus the derived
/// heartbeat age and staleness flag.
fn worker_json(w: &ActiveWorkerRow, now: i64) -> Value {
    let age = heartbeat_age(w, now);
    json!({
        "worker_uuid": w.worker_uuid,
        "issue_id": w.issue_id,
        "role": w.role.to_string(),
        "round": w.round,
        "workspace_path": w.workspace_path.display().to_string(),
        "pid": w.pid,
        "spawned_at": w.spawned_at,
        "last_heartbeat": w.last_heartbeat,
        "heartbeat_age_secs": age,
        "stale": age > STALE_THRESHOLD_SECS,
    })
}

// ============================================================================
// events
// ============================================================================

/// `vetinari events [--issue N] [--tail K]` — the trailing slice of the
/// `events` stream (the queryable authority `events.jsonl` mirrors), newest
/// entries last.
fn cmd_events(args: &Cli) -> Result<()> {
    let dir = resolve_orchestrator_dir(args.orchestrator_dir.as_deref())?;
    let state = open_state(&dir)?;
    let tail = args.tail.unwrap_or(DEFAULT_EVENT_TAIL);

    // With an issue filter we must scan the whole stream (the getters filter on
    // recency, not issue) and keep the trailing K; without one, `recent_events`
    // fetches exactly K newest, which we reverse to chronological order.
    let events: Vec<EventRow> = match args.issue {
        Some(id) => {
            let key = id.to_string();
            let mut all: Vec<EventRow> = state
                .all_events()
                .into_diagnostic()?
                .into_iter()
                .filter(|e| e.issue_id.as_deref() == Some(key.as_str()))
                .collect();
            if all.len() > tail {
                all = all.split_off(all.len() - tail);
            }
            all
        }
        None => {
            let mut recent = state
                .recent_events(u32::try_from(tail).unwrap_or(u32::MAX))
                .into_diagnostic()?;
            recent.reverse(); // recent_events is newest-first; show oldest-first
            recent
        }
    };

    if args.json {
        let arr: Vec<Value> = events.iter().map(event_json).collect();
        return write_json(&Value::Array(arr));
    }
    if events.is_empty() {
        return write_out("no events\n");
    }
    let rows: Vec<Vec<String>> = events
        .iter()
        .map(|e| {
            vec![
                e.ts.to_string(),
                e.kind.to_string(),
                e.issue_id
                    .clone()
                    .map(|i| format!("#{i}"))
                    .unwrap_or_else(|| "-".to_string()),
                e.worker_uuid
                    .as_deref()
                    .map(short_uuid)
                    .unwrap_or_else(|| "-".to_string()),
                compact_json(&e.payload),
            ]
        })
        .collect();
    write_out(&render_table(
        &["TS", "KIND", "ISSUE", "WORKER", "PAYLOAD"],
        &rows,
    ))
}

/// The JSON projection of an [`EventRow`] (payload kept as a nested value).
fn event_json(e: &EventRow) -> Value {
    json!({
        "id": e.id,
        "ts": e.ts,
        "kind": e.kind.to_string(),
        "issue_id": e.issue_id,
        "worker_uuid": e.worker_uuid,
        "payload": e.payload,
    })
}

// ============================================================================
// crossbridge
// ============================================================================

/// `vetinari crossbridge` — inbound/outbound crossbridge issues as they exist
/// *today*, before the crossbridge integration is built.
///
/// crossbridge ingestion (the embedded server, the answer state machine, the
/// `phase:awaiting-inbound-approval` gate) is a later step of the swarm-kickoff
/// spec (§1). Until then there is no live socket, no answer substate authority,
/// and no degraded flag. This view therefore reads only what is already
/// representable: crosslink issues carrying the `xb:*` marker labels. It prints
/// a clear "integration not yet active" note and never stubs fake data.
///
/// Forward-compatibility note: the answer substate (`answer_pending` /
/// `answer_sent` / `answer_unreachable`) and the `degraded` flag will become
/// authoritative `state.db` columns in a later step (review B5). They are shown
/// as `-` here; when they land, join them in from the issue's `phase_substate`.
fn cmd_crossbridge(args: &Cli) -> Result<()> {
    let dir = resolve_orchestrator_dir(args.orchestrator_dir.as_deref())?;
    let crosslink = open_crosslink(&dir)?;

    // Best-effort join to the issue's persisted substate — forward-compatible
    // with the answer-substate columns that arrive in a later step. A stopped or
    // absent state.db is not fatal to this crosslink-only view.
    let substate_of: std::collections::BTreeMap<i64, String> = match open_state(&dir) {
        Ok(state) => state
            .list_issues()
            .into_diagnostic()?
            .into_iter()
            .filter_map(|r| {
                let id = r.issue_id.parse::<i64>().ok()?;
                Some((id, r.phase_substate.unwrap_or_else(|| "-".to_string())))
            })
            .collect(),
        Err(_) => std::collections::BTreeMap::new(),
    };

    let inbound = crosslink
        .list_by_label("open", XB_INBOUND_LABEL)
        .into_diagnostic()
        .wrap_err("list inbound crossbridge issues")?;
    let outbound = crosslink
        .list_by_label("open", XB_OUTBOUND_LABEL)
        .into_diagnostic()
        .wrap_err("list outbound crossbridge issues")?;

    if args.json {
        return write_json(&json!({
            "integration_active": false,
            "note": "crossbridge integration not yet active (swarm-kickoff spec §1, not built)",
            "inbound": inbound.iter().map(|i| xb_issue_json(i, &substate_of)).collect::<Vec<_>>(),
            "outbound": outbound.iter().map(|i| xb_issue_json(i, &substate_of)).collect::<Vec<_>>(),
        }));
    }

    let mut out = String::new();
    out.push_str("crossbridge integration not yet active (swarm-kickoff spec §1, not built).\n");
    out.push_str("Showing crosslink issues carrying xb:* marker labels only.\n\n");
    out.push_str(&xb_section("INBOUND", &inbound, &substate_of));
    out.push('\n');
    out.push_str(&xb_section("OUTBOUND", &outbound, &substate_of));
    write_out(&out)
}

/// Render one labelled crossbridge section (inbound or outbound) as a table.
fn xb_section(
    title: &str,
    issues: &[IssueInfo],
    substate_of: &std::collections::BTreeMap<i64, String>,
) -> String {
    if issues.is_empty() {
        return format!("{title}: none\n");
    }
    let rows: Vec<Vec<String>> = issues
        .iter()
        .map(|i| {
            vec![
                format!("#{}", i.id),
                i.title.clone(),
                label_value(&i.labels, XB_SOURCE_PREFIX),
                label_value(&i.labels, XB_STATUS_PREFIX),
                label_value(&i.labels, XB_REF_PREFIX),
                substate_of
                    .get(&i.id)
                    .cloned()
                    .unwrap_or_else(|| "-".to_string()),
            ]
        })
        .collect();
    format!(
        "{title}:\n{}",
        render_table(
            &[
                "ISSUE",
                "TITLE",
                "SOURCE",
                "XB_STATUS",
                "XB_REF",
                "SUBSTATE"
            ],
            &rows,
        )
    )
}

/// The JSON projection of one crossbridge issue.
fn xb_issue_json(i: &IssueInfo, substate_of: &std::collections::BTreeMap<i64, String>) -> Value {
    json!({
        "id": i.id,
        "title": i.title,
        "peer_slug": label_value(&i.labels, XB_SOURCE_PREFIX),
        "xb_status": label_value(&i.labels, XB_STATUS_PREFIX),
        "xb_ref": label_value(&i.labels, XB_REF_PREFIX),
        "answer_substate": substate_of.get(&i.id).cloned().unwrap_or_else(|| "-".to_string()),
    })
}

/// The suffix of the first label starting with `prefix`, or `-` if none.
fn label_value(labels: &[String], prefix: &str) -> String {
    labels
        .iter()
        .find_map(|l| l.strip_prefix(prefix))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".to_string())
}

// ============================================================================
// Shared helpers
// ============================================================================

/// Resolve the `.orchestrator/` directory: the `--orchestrator-dir` override
/// (canonicalized) if given, else discovered by walking up from the current
/// directory (mirrors how `crosslink_api` discovers `.crosslink/`).
fn resolve_orchestrator_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        if !dir.is_dir() {
            bail!("`--orchestrator-dir {}` is not a directory", dir.display());
        }
        return dir
            .canonicalize()
            .into_diagnostic()
            .wrap_err_with(|| format!("canonicalize `{}`", dir.display()));
    }
    let start = std::env::current_dir()
        .into_diagnostic()
        .wrap_err("determine current directory")?;
    let mut cursor: &Path = &start;
    loop {
        let candidate = cursor.join(ORCHESTRATOR_DIR);
        if candidate.is_dir() {
            return candidate
                .canonicalize()
                .into_diagnostic()
                .wrap_err_with(|| format!("canonicalize `{}`", candidate.display()));
        }
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => break,
        }
    }
    bail!(
        "no `{ORCHESTRATOR_DIR}/` directory found from `{}` upward — \
         run from inside the repo or pass `--orchestrator-dir PATH`",
        start.display()
    )
}

/// Open `state.db` under `orchestrator_dir` read-only (the concurrency-safe
/// second connection — see the module docs).
fn open_state(orchestrator_dir: &Path) -> Result<StateDb> {
    let db_path = orchestrator_dir.join("state.db");
    StateDb::open_read_only(&db_path)
        .map_err(miette::Report::new)
        .wrap_err_with(|| format!("open state.db read-only at `{}`", db_path.display()))
}

/// Open the crosslink repository whose root is the parent of the
/// `.orchestrator/` directory (its sibling `.crosslink/`).
fn open_crosslink(orchestrator_dir: &Path) -> Result<CrosslinkRepo> {
    let root = orchestrator_dir
        .parent()
        .ok_or_else(|| miette!("`{}` has no parent repo root", orchestrator_dir.display()))?;
    CrosslinkRepo::open(root)
        .map_err(miette::Report::new)
        .wrap_err_with(|| format!("open crosslink repo at `{}`", root.display()))
}

/// First 8 characters of a worker uuid — enough to identify it in a table.
fn short_uuid(uuid: &str) -> String {
    uuid.chars().take(8).collect()
}

/// Current time as unix seconds (0 before the epoch, never panics).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A single-line, compact JSON rendering of a value for a table cell.
fn compact_json(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "<unserializable>".to_string())
}

/// Render a fixed-width text table: header row plus body, columns padded to the
/// widest cell, two spaces between columns, the last column left un-padded.
fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    push_row(
        &mut out,
        &headers.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
        &widths,
    );
    for row in rows {
        push_row(&mut out, row, &widths);
    }
    out
}

/// Append one padded table row (last column not padded, no trailing spaces).
fn push_row(out: &mut String, cells: &[String], widths: &[usize]) {
    let last = cells.len().saturating_sub(1);
    for (i, cell) in cells.iter().enumerate() {
        if i == last {
            out.push_str(cell);
        } else {
            let width = widths.get(i).copied().unwrap_or(0);
            let pad = width.saturating_sub(cell.chars().count());
            out.push_str(cell);
            for _ in 0..pad + 2 {
                out.push(' ');
            }
        }
    }
    out.push('\n');
}

/// Write a JSON value to stdout, pretty-printed with a trailing newline.
fn write_json(v: &Value) -> Result<()> {
    let s = serde_json::to_string_pretty(v)
        .into_diagnostic()
        .wrap_err("serialize JSON output")?;
    write_out(&format!("{s}\n"))
}

/// Write a string to stdout, mapping a broken-pipe / I/O failure to a
/// diagnostic rather than panicking (no `unwrap`/`expect` on the write path).
fn write_out(s: &str) -> Result<()> {
    std::io::stdout()
        .write_all(s.as_bytes())
        .into_diagnostic()
        .wrap_err("write to stdout")
}
