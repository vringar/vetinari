//! Session lifecycle: ensure a long-lived headless zellij session exists.

use crate::error::{Result, ZellijError};
use crate::zellij::run_zellij;

/// A handle to a zellij session the orchestrator hosts workers in.
///
/// Holding a `SessionHandle` does not pin the session alive — it is just the
/// session's name, threaded into pane operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHandle {
    /// The session name (e.g. `vdd-orchestrator`).
    pub name: String,
}

/// Ensure a headless zellij session named `name` exists, creating a detached
/// (background, no attached client) one if it does not.
///
/// Idempotent: calling it for a session that already exists is a no-op. A
/// human can later `zellij attach <name>` to inspect a worker live.
pub fn session_ensure(name: &str) -> Result<SessionHandle> {
    if !session_exists(name)? {
        // `--create-background` creates the session detached and exits without
        // attaching — exactly the headless model the orchestrator needs.
        run_zellij(&["attach", "--create-background", name])?;
    }
    Ok(SessionHandle {
        name: name.to_owned(),
    })
}

/// Whether a live zellij session named `name` currently exists.
fn session_exists(name: &str) -> Result<bool> {
    // `list-sessions` exits non-zero when there are no sessions at all; that is
    // not an error for our purposes — it just means the session is absent.
    match run_zellij(&["list-sessions", "--short", "--no-formatting"]) {
        Ok(stdout) => Ok(stdout.lines().any(|line| line.trim() == name)),
        Err(ZellijError::CommandFailed { .. }) => Ok(false),
        Err(other) => Err(other),
    }
}
