//! vetinari orchestrator entry point — wires the build pump into a headless
//! run against the current repository (REQ-16, REQ-13, AC-11a/AC-11b).
//!
//! Startup: resolve the `bwrap` store-path pin (REQ-4a), open `state.db` and
//! `events.jsonl` (REQ-2, REQ-14), ensure the long-lived headless zellij
//! session (REQ-1d), then build the [`BuildPump`] from its collaborators and run
//! its tick loop. The real per-issue work — implement → QA → land — lives in the
//! pump; this binary is deliberately thin (the dogfood integration test is the
//! authoritative proof of the loop).

use std::path::Path;
use std::time::Duration;

use miette::IntoDiagnostic;
use tracing_subscriber::EnvFilter;
use vetinari_crossbridge_api::{ServeCfg, ServerHandle};
use vetinari_crosslink_api::CrosslinkRepo;
use vetinari_error::SpawnError;

use orchestrator::config::{CrossbridgeConfig, OrchestratorConfig};
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

    let pinned = std::env::var("VDD_BWRAP_PIN")
        .into_diagnostic()
        .map_err(|e| {
            miette::miette!(
                help =
                    "Enter the dev shell with `nix-shell` — the shellHook exports VDD_BWRAP_PIN.",
                "{e}"
            )
        })?;
    tracing::info!(bwrap = %pinned, "bwrap store-path pin resolved");

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

    // REQ-15 (AC-17, AC-18): deterministic crash recovery. BEFORE the pump loop,
    // re-derive filesystem ground truth for every non-terminal issue and any
    // `active_workers` row and advance / repeat / roll back idempotently — clean
    // a crashed worker's workspace, replay an interrupted (idempotent)
    // translation, or resume a mid-flight landing. This leaves each issue in a
    // state the pump can then pick up and drive. Recovery is idempotent, so a
    // restart mid-recovery re-runs it harmlessly.
    let recovered = orchestrator::recovery::recover(&state, &log, &manager, Some(&crosslink))?;
    for action in &recovered {
        tracing::info!(?action, "crash recovery reconciled an issue");
    }
    tracing::info!(
        reconciled = recovered.len(),
        "crash recovery complete — entering the pump loop"
    );

    // Spec §1.2 / §1.4: the embedded crossbridge federation server. OFF by
    // default — see [`start_crossbridge`]. Started here, strictly AFTER
    // `recover()` above and BEFORE the pump loop below, so the server can never
    // create an `xb:inbound` issue mid recovery-scan (review N4). The handle is
    // bound to a variable that lives across `run_loop`, holding the server for
    // the whole process lifetime; when disabled it is simply `None`.
    let _crossbridge = start_crossbridge(&config.crossbridge, &root)?;

    let pump = BuildPump::new(config, state, log, manager, spawner, crosslink);

    tracing::info!("build pump ready — entering tick loop (Ctrl-C to stop)");
    run_loop(&pump)
}

/// Start the embedded crossbridge federation server iff `[crossbridge] enabled`
/// is `true`; otherwise a strict no-op (spec §1.2, §1.4, step 4).
///
/// # Off by default — the load-bearing safety property
///
/// When `cfg.enabled` is `false` (the default, and the state of any node that
/// never writes a `[crossbridge]` section) this returns `Ok(None)` and does
/// **nothing**: no `serve()`, no socket opened, no server thread, no inbound
/// issues, no behavior change whatsoever. This is the first code that can start
/// a network-facing server inside the orchestrator, so safety-by-default is the
/// contract: a default build is byte-identical to a crossbridge-unaware one.
///
/// # Sequencing (spec §1.4)
///
/// The caller invokes this **strictly after** `recover()` and **before** the
/// pump loop. That ordering matters: the embedded server is a sanctioned second
/// writer to `.crosslink/issues.db`, and starting it before the recovery scan
/// completes would let a peer's `SubmitIssue` create an `xb:inbound` issue mid
/// scan (review N4). After recovery, a newly created inbound issue is just
/// another issue the next pump tick observes.
///
/// # Inbound work stays pump-ignored (spec §1.2, step 4 scope)
///
/// The server creates inbound issues with `xb:inbound` and **no** `phase:*`
/// label. The pump's strict pickup (`pump.rs:463-494` — graphed + open +
/// unblocked) ignores unphased issues, so inbound work is *not* driven by this
/// step. Picking it up is deliberately deferred to the later approval-gate step;
/// this step only makes the server *run*.
///
/// # Lifetime & shutdown
///
/// The returned [`ServerHandle`] must be held for the process lifetime (the
/// caller binds it across `run_loop`): dropping it asks the server thread to
/// stop, bounded. The MVP has **no** clean-shutdown path — the process is
/// killed and re-recovers on restart (`run_loop` docs) — so we neither install
/// signal handling here (out of scope for this step) nor call `shutdown()`; when
/// the process dies, the detached server thread dies with it. If a clean-
/// shutdown path is ever added, call `handle.shutdown()` there (it is already
/// bounded, detach-on-timeout) — never in a way that blocks `run_loop`.
///
/// # Errors
///
/// A failed slug derivation or `serve()` is a **fatal startup error** and
/// bubbles like the other startup `?`s: the orchestrator must not silently
/// continue with a dead server when the operator asked for one.
fn start_crossbridge(cfg: &CrossbridgeConfig, root: &Path) -> miette::Result<Option<ServerHandle>> {
    if !cfg.enabled {
        // Default path: NOTHING happens. No server, no socket, no inbound
        // issues — the pump is byte-identical to a crossbridge-unaware build.
        return Ok(None);
    }

    // Derive our slug via crossbridge's own precedence (config override →
    // `$CROSSBRIDGE_OWN_SLUG` → `origin` remote). Reusing crossbridge's
    // derivation is the point: a divergent reimplementation would desync us
    // from our peers (review N7).
    let slug = vetinari_crossbridge_api::own_slug(root, cfg.slug.as_deref())?;
    // An unset socket_root falls back to the crossbridge default, resolved by
    // the membrane crate so the orchestrator never names crossbridge's
    // socket-layout policy itself.
    let socket_root = cfg
        .socket_root
        .clone()
        .unwrap_or_else(vetinari_crossbridge_api::default_socket_root);

    let serve_cfg = ServeCfg {
        slug: slug.clone(),
        group: cfg.group.clone(),
        repo_root: root.to_path_buf(),
        socket_root: socket_root.clone(),
    };
    let handle = vetinari_crossbridge_api::serve(serve_cfg)?;
    tracing::info!(
        slug = %slug,
        group = %cfg.group,
        socket_root = %socket_root.display(),
        "embedded crossbridge server started — inbound issues stay unphased and pump-ignored until a human graphs them"
    );
    Ok(Some(handle))
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
