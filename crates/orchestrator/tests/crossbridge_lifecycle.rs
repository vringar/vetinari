//! Config-driven embedded-crossbridge lifecycle (spec §1.2, §1.4, step 4).
//!
//! `main.rs::start_crossbridge` is a private binary function, so these tests
//! exercise the operator-visible path it is built from: an
//! `.orchestrator/config.toml` `[crossbridge]` section parsed into
//! [`OrchestratorConfig`], then the exact field mapping into
//! `crossbridge_api::ServeCfg` that `start_crossbridge` performs. The goal is to
//! prove the *config → serve → bounded-shutdown* wiring stands up an embedded
//! server and tears it down without a live peer or supervisor — reusing
//! `crossbridge_api`'s own `serve_shuts_down_cleanly_via_token` approach (an
//! empty crosslink DB lets `run` reach its select loop; no listener socket is
//! ever bound, so no supervisor is needed).
//!
//! # What this does NOT cover (the sandbox / peer gap)
//!
//! A real peer `submit` needs the crossbridge supervisor + socket topology,
//! which is not available in this sandbox (per-node MEMORY: crossbridge requires
//! a supervisor; the socket dir is not mounted). So an end-to-end "a peer
//! submits and an `xb:inbound` issue appears, unphased and pump-ignored" test is
//! out of reach here and is not attempted.

use std::path::PathBuf;

use orchestrator::config::{CrossbridgeConfig, OrchestratorConfig};
use vetinari_crossbridge_api::{serve, CrossbridgeError, ServeCfg};

/// The default (`enabled = false`) config yields no server: `start_crossbridge`
/// would short-circuit to `Ok(None)`. This asserts the *decision input* — the
/// parsed flag — is `false` for an absent section, which is the strict no-op
/// safety property this whole step rests on.
#[test]
fn disabled_config_is_the_no_op_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A config that never mentions crossbridge — the common case.
    std::fs::write(
        dir.path().join(orchestrator::config::CONFIG_FILE),
        "poll_interval_ms = 500\n",
    )
    .expect("write config");
    let cfg = OrchestratorConfig::load(dir.path()).expect("load");
    assert!(
        !cfg.crossbridge.enabled,
        "absent [crossbridge] must leave the server disabled — no serve() is reached"
    );
    assert_eq!(cfg.crossbridge, CrossbridgeConfig::default());
}

/// The `enabled = true` path, driven from a parsed config exactly as
/// `start_crossbridge` maps it: an explicit `slug` (so no `origin` remote is
/// needed) and a temp `socket_root`. With an empty crosslink DB present, the
/// server thread reaches its select loop; shutdown via the handle must be
/// bounded — `join()` returns either a clean `Ok(())` or, if the thread is
/// parked, the deliberate `ShutdownTimedOut` — never hangs.
#[test]
fn enabled_config_serves_and_shuts_down_bounded() {
    let repo = tempfile::tempdir().expect("repo tempdir");
    // Build a real, empty crosslink DB so `run` proceeds past its DB check into
    // the select loop where the shutdown token is honored (mirrors
    // crossbridge_api's own lifecycle test).
    let crosslink_dir = repo.path().join(".crosslink");
    std::fs::create_dir_all(&crosslink_dir).expect("create .crosslink");
    let _db =
        crosslink::db::Database::open(&crosslink_dir.join("issues.db")).expect("open crosslink db");

    // Parse the operator's config shape (spec §1.2 pilot config).
    let orch_dir = repo.path().join(".orchestrator");
    std::fs::create_dir_all(&orch_dir).expect("create .orchestrator");
    let socket_root = repo.path().join("run");
    std::fs::write(
        orch_dir.join(orchestrator::config::CONFIG_FILE),
        format!(
            "[crossbridge]\nenabled = true\ngroup = \"reversing\"\nslug = \"firmware\"\nsocket_root = {:?}\n",
            socket_root.to_string_lossy()
        ),
    )
    .expect("write config");
    let cfg = OrchestratorConfig::load(&orch_dir).expect("load");
    assert!(cfg.crossbridge.enabled);

    // The exact mapping `start_crossbridge` performs (slug override honored;
    // socket_root taken from config).
    let slug = vetinari_crossbridge_api::own_slug(repo.path(), cfg.crossbridge.slug.as_deref())
        .expect("explicit slug override resolves without a repo");
    assert_eq!(slug, "firmware");
    let resolved_socket_root: PathBuf = cfg
        .crossbridge
        .socket_root
        .clone()
        .unwrap_or_else(vetinari_crossbridge_api::default_socket_root);
    assert_eq!(resolved_socket_root, socket_root);

    let serve_cfg = ServeCfg {
        slug,
        group: cfg.crossbridge.group.clone(),
        repo_root: repo.path().to_path_buf(),
        socket_root: resolved_socket_root,
    };
    let handle = serve(serve_cfg).expect("server thread spawns — serve() returns a live handle");
    handle.shutdown();
    match handle.join() {
        Ok(()) => {}
        // A parked untrusted-peer read can defeat cooperative cancellation; the
        // bound then detaches the thread. Either outcome is a *bounded* shutdown
        // — the property under test — never a hang.
        Err(CrossbridgeError::ShutdownTimedOut { .. }) => {}
        Err(other) => panic!("unexpected shutdown error: {other:?}"),
    }
}
