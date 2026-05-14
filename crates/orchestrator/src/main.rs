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

    tracing::warn!("orchestrator is a skeleton — pump, spawn, landing all unimplemented (see crosslink issues #8..#19)");
    Ok(())
}
