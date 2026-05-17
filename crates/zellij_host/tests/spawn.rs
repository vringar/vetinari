//! AC-27: a worker spawn produces a live zellij pane that closes on worker
//! exit, driven entirely through the `zellij_host` adapter.
//!
//! This is a real integration test: it creates an actual headless zellij
//! session and pane, so it needs `zellij` on PATH (the nix dev shell provides
//! it). It uses a process-unique session name so concurrent runs and any real
//! `vdd-orchestrator` session are never disturbed, and kills that session on
//! the way out.

use std::process::Command;
use std::time::{Duration, Instant};

use vetinari_zellij_host::{pane_alive, pane_create, session_ensure};

/// Kills the test's zellij session when dropped, so an assertion failure still
/// cleans up.
struct SessionGuard {
    name: String,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        // Best effort: the session may already be gone.
        let _ = Command::new("zellij")
            .args(["kill-session", &self.name])
            .output();
    }
}

/// Poll `pane_alive` until it returns `false` or `timeout` elapses.
fn wait_until_closed(pane: &vetinari_zellij_host::PaneHandle, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match pane_alive(pane) {
            Ok(false) => return true,
            Ok(true) => std::thread::sleep(Duration::from_millis(500)),
            Err(err) => panic!("pane_alive failed while polling: {err}"),
        }
    }
    false
}

#[test]
fn worker_spawn_produces_a_pane_that_closes_on_exit() {
    let session_name = format!("vetinari-ac27-{}", std::process::id());
    let _guard = SessionGuard {
        name: session_name.clone(),
    };

    let session = session_ensure(&session_name).expect("ensure headless session");

    // A throwaway working directory; the worker command writes a marker into
    // it from an environment variable, which proves `env` was applied.
    let cwd = tempfile::tempdir().expect("create tempdir");
    let command = [
        "sh",
        "-c",
        "printf %s \"$VETINARI_AC27\" > marker.txt; sleep 4",
    ];
    let env = [("VETINARI_AC27", "applied")];

    let pane = pane_create(&session, "implementer-9999-r0", &command, &env, cwd.path())
        .expect("create worker pane");
    assert_eq!(pane.session, session_name);
    assert_eq!(pane.name, "implementer-9999-r0");

    // The pane is alive while the worker's `sleep` runs.
    assert!(
        pane_alive(&pane).expect("query pane liveness"),
        "pane should be alive while the worker command runs"
    );

    // It closes itself once the command exits (panes use --close-on-exit).
    assert!(
        wait_until_closed(&pane, Duration::from_secs(20)),
        "pane should close after the worker command exits"
    );

    // The marker proves the `env` argument reached the worker process.
    let marker = cwd.path().join("marker.txt");
    assert_eq!(
        std::fs::read_to_string(&marker).ok().as_deref(),
        Some("applied"),
        "worker command should have seen VETINARI_AC27 from `env`"
    );
}
