use miette::IntoDiagnostic;
use tracing_subscriber::EnvFilter;

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

    let pinned = std::env::var("VDD_CLAUDE_SANDBOX_PIN")
        .into_diagnostic()
        .map_err(|e| {
            miette::miette!(
                help = "Enter the dev shell with `nix develop` — the flake exports VDD_CLAUDE_SANDBOX_PIN.",
                "{e}"
            )
        })?;
    tracing::info!(claude_sandbox = %pinned, "claude-sandbox pin resolved");

    // REQ-2 / AC-2: the orchestrator's authoritative state lives in
    // `.orchestrator/state.db`. Open (and, on first run, migrate) it now so a
    // missing or unwritable state directory fails fast at startup rather than
    // mid-tick. The pump (#15) takes ownership of the handle; the skeleton
    // only proves the migration runs.
    let state_path = std::path::PathBuf::from(".orchestrator/state.db");
    orchestrator::state::StateDb::open(&state_path)?;
    tracing::info!(state_db = %state_path.display(), "state.db ready (schema migrated)");

    tracing::warn!("orchestrator is a skeleton — pump, spawn, landing all unimplemented (see crosslink issues #8..#19)");
    Ok(())
}
