//! vetinari orchestrator entry point — wires the build pump into a headless
//! run against the current repository (REQ-16, REQ-13, AC-11a/AC-11b).
//!
//! Startup: resolve the `claude-sandbox` pin (REQ-4a), open `state.db` and
//! `events.jsonl` (REQ-2, REQ-14), ensure the long-lived headless zellij
//! session (REQ-1d), then build the [`BuildPump`] from its collaborators and run
//! its tick loop. The real per-issue work — implement → QA → land — lives in the
//! pump; this binary is deliberately thin (the dogfood integration test is the
//! authoritative proof of the loop).

use std::time::Duration;

use miette::IntoDiagnostic;
use tracing_subscriber::EnvFilter;
use vetinari_crosslink_api::CrosslinkRepo;
use vetinari_error::SpawnError;

use orchestrator::config::OrchestratorConfig;
use orchestrator::events::{EventLog, ORCHESTRATOR_DIR};
use orchestrator::pump::BuildPump;
use orchestrator::spawn::Spawner;
use orchestrator::state::StateDb;
use orchestrator::workspace::WorkspaceManager;

/// Name of the long-lived headless zellij session that hosts every worker
/// pane (REQ-1d). Fixed, not configurable — humans and other agents rely on
/// it to `zellij attach` for live inspection.
const SESSION_NAME: &str = "vdd-orchestrator";

fn main() -> miette::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    miette::set_panic_hook();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "vetinari orchestrator starting"
    );

    let root = std::env::current_dir().into_diagnostic()?;
    let orchestrator_dir = root.join(ORCHESTRATOR_DIR);

    let pinned = std::env::var("VDD_CLAUDE_SANDBOX_PIN")
        .into_diagnostic()
        .map_err(|e| {
            miette::miette!(
                help = "Enter the dev shell with `nix develop` — the flake exports VDD_CLAUDE_SANDBOX_PIN.",
                "{e}"
            )
        })?;
    tracing::info!(claude_sandbox = %pinned, "claude-sandbox pin resolved");

    // REQ-13: the concurrency budget, poll cadence, timeouts, and dogfood worker
    // command. An absent config.toml yields all-defaults.
    let config = OrchestratorConfig::load(&orchestrator_dir)?;
    tracing::info!(
        poll_interval_ms = config.poll_interval_ms,
        max_concurrent_agents = config.max_concurrent_agents,
        "orchestrator config loaded"
    );

    // REQ-2 / AC-2: authoritative state in `.orchestrator/state.db`. Open (and,
    // on first run, migrate) it now so a missing/unwritable state directory
    // fails fast at startup rather than mid-tick.
    let state = StateDb::open(orchestrator_dir.join("state.db"))?;
    tracing::info!("state.db ready (schema migrated)");

    // REQ-14: reconcile the `events.jsonl` mirror against the SQLite authority
    // at startup, then hold the append-only handle for the loop.
    let log = EventLog::rebuild_from(&state, &orchestrator_dir)?;

    // REQ-5a: the shared `.jj/` gate for workspace prep and landing.
    let manager = WorkspaceManager::load(&root)?;

    // REQ-3: the single-writer crosslink handle — the poll source and comment /
    // label sink.
    let crosslink = CrosslinkRepo::open(&root)?;

    // REQ-1d: every worker is hosted in a pane of a long-lived headless zellij
    // session. Ensure it exists (create-or-attach is idempotent).
    let session = vetinari_zellij_host::session_ensure(SESSION_NAME).map_err(|e| {
        SpawnError::ZellijSessionUnavailable {
            session_name: SESSION_NAME.to_string(),
            source: Some(Box::new(e)),
        }
    })?;
    tracing::info!(
        session = SESSION_NAME,
        "zellij worker-host session ready — run `zellij attach vdd-orchestrator` to inspect workers live"
    );

    // REQ-4a: the pin guard runs inside real `claude` spawns; the pump's Direct
    // dogfood worker skips it. Build the spawner from the environment pin.
    let spawner = Spawner::from_env(session, &root)?;

    let pump = BuildPump::new(config, state, log, manager, spawner, crosslink);

    tracing::info!("build pump ready — entering tick loop (Ctrl-C to stop)");
    run_loop(&pump)
}

/// The headless tick loop: poll, drive ready issues, sleep, repeat.
///
/// A `PumpError` (crosslink unreachable, state.db broken) is fatal and bubbles
/// out; issue-level failures are handled in-band by the pump and never abort the
/// loop. There is no clean-shutdown signal handling in the MVP — the process is
/// stopped externally. Every phase transition is persisted to `state.db` before
/// the sleep, and a drivable issue is re-selected from `state.db` on the next
/// tick, so a restart re-picks-up an issue left mid-flight and re-drives it from
/// a fresh workspace. Full crash-recovery of an *in-flight worker* from its
/// persisted `active_workers` row (killing a survivor, resuming a landing
/// substate) is NOT done here — that is deferred to #16 P2 (REQ-15); P1 only
/// persists the state P2 needs.
fn run_loop(pump: &BuildPump) -> miette::Result<()> {
    let interval: Duration = pump.poll_interval();
    loop {
        let outcomes = pump.tick()?;
        for (issue_id, outcome) in outcomes {
            tracing::info!(issue = issue_id, ?outcome, "issue driven this tick");
        }
        std::thread::sleep(interval);
    }
}
