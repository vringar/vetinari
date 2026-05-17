//! Pane lifecycle: create a worker pane, check it, close it.

use std::path::Path;

use crate::error::{Result, ZellijError};
use crate::session::SessionHandle;
use crate::zellij::run_zellij;

/// A handle to a single pane hosting one worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneHandle {
    /// Name of the session the pane lives in.
    pub session: String,
    /// Human-readable pane name (e.g. `implementer-42-r0`).
    pub name: String,
    /// zellij's pane id, in `terminal_<n>` / `plugin_<n>` form — the token
    /// `zellij action --pane-id` accepts.
    pub pane_id: String,
}

/// Create a new pane named `name` in `session`, running `command` with the
/// given `env` and working directory `cwd`.
///
/// `command` is an argv: the first element is the program, the rest its
/// arguments; it must be non-empty. The pane closes automatically when the
/// command exits, so [`pane_alive`] reports `false` once a worker finishes.
///
/// zellij has no per-pane environment API, so `env` is applied by prefixing
/// the command with `env KEY=VALUE …`. (A program whose name contains `=`
/// would therefore be misparsed by `env`; worker commands never are.)
pub fn pane_create(
    session: &SessionHandle,
    name: &str,
    command: &[&str],
    env: &[(&str, &str)],
    cwd: &Path,
) -> Result<PaneHandle> {
    if command.is_empty() {
        return Err(ZellijError::EmptyCommand);
    }
    let cwd = cwd.to_string_lossy().into_owned();
    let env_assignments: Vec<String> = env
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();

    // zellij --session <s> action new-pane --name <n> --cwd <c> --close-on-exit -- <argv>
    let mut call: Vec<&str> = vec![
        "--session",
        &session.name,
        "action",
        "new-pane",
        "--name",
        name,
        "--cwd",
        &cwd,
        "--close-on-exit",
        "--",
    ];
    if !env_assignments.is_empty() {
        call.push("env");
        call.extend(env_assignments.iter().map(String::as_str));
    }
    call.extend(command.iter().copied());

    let stdout = run_zellij(&call)?;
    let pane_id = extract_pane_id(&stdout).ok_or_else(|| ZellijError::OutputParse {
        operation: "pane_create".to_owned(),
        detail: format!("`zellij new-pane` returned no pane id (output: {stdout:?})"),
    })?;
    Ok(PaneHandle {
        session: session.name.clone(),
        name: name.to_owned(),
        pane_id,
    })
}

/// Whether `pane` is still open.
///
/// Returns `false` once the pane has closed — which, because panes are created
/// with `--close-on-exit`, means the worker's command has exited.
pub fn pane_alive(pane: &PaneHandle) -> Result<bool> {
    let (is_plugin, id) = split_pane_id(&pane.pane_id)?;
    let stdout = run_zellij(&["--session", &pane.session, "action", "list-panes", "--json"])?;
    let panes: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|err| ZellijError::OutputParse {
            operation: "pane_alive".to_owned(),
            detail: format!("`list-panes --json` was not valid JSON: {err}"),
        })?;
    let entries = panes.as_array().ok_or_else(|| ZellijError::OutputParse {
        operation: "pane_alive".to_owned(),
        detail: "`list-panes --json` did not return a JSON array".to_owned(),
    })?;
    for entry in entries {
        let entry_id = entry.get("id").and_then(serde_json::Value::as_u64);
        let entry_is_plugin = entry
            .get("is_plugin")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if entry_id == Some(id) && entry_is_plugin == is_plugin {
            // A pane still listed but flagged `exited` is a held/finished
            // command pane — not alive.
            let exited = entry
                .get("exited")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            return Ok(!exited);
        }
    }
    // Not in the list at all: the pane closed itself on command exit.
    Ok(false)
}

/// Close `pane`.
///
/// Closing a pane that has already closed itself is reported by `zellij` as a
/// failure; callers that treat close as best-effort cleanup should ignore a
/// resulting [`ZellijError::CommandFailed`].
pub fn pane_close(pane: &PaneHandle) -> Result<()> {
    run_zellij(&[
        "--session",
        &pane.session,
        "action",
        "close-pane",
        "--pane-id",
        &pane.pane_id,
    ])?;
    Ok(())
}

/// Pick the pane id out of `zellij new-pane`'s output: the last line that is a
/// bare `terminal_<n>` / `plugin_<n>` token.
fn extract_pane_id(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .rfind(|line| is_pane_id(line))
        .map(str::to_owned)
}

/// Whether `token` is a bare zellij pane id (`terminal_<digits>` /
/// `plugin_<digits>`).
fn is_pane_id(token: &str) -> bool {
    let digits = token
        .strip_prefix("terminal_")
        .or_else(|| token.strip_prefix("plugin_"));
    matches!(digits, Some(d) if !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Split a pane id into `(is_plugin, numeric_id)`.
fn split_pane_id(pane_id: &str) -> Result<(bool, u64)> {
    let (is_plugin, digits) = if let Some(digits) = pane_id.strip_prefix("terminal_") {
        (false, digits)
    } else if let Some(digits) = pane_id.strip_prefix("plugin_") {
        (true, digits)
    } else {
        return Err(ZellijError::OutputParse {
            operation: "pane_alive".to_owned(),
            detail: format!("pane id `{pane_id}` is not a terminal_/plugin_ token"),
        });
    };
    let id = digits
        .parse::<u64>()
        .map_err(|_| ZellijError::OutputParse {
            operation: "pane_alive".to_owned(),
            detail: format!("pane id `{pane_id}` has a non-numeric index"),
        })?;
    Ok((is_plugin, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_pane_id_from_trailing_line() {
        assert_eq!(
            extract_pane_id("some log line\nterminal_7\n").as_deref(),
            Some("terminal_7")
        );
        assert_eq!(extract_pane_id("plugin_3").as_deref(), Some("plugin_3"));
        assert_eq!(extract_pane_id("no id here\n"), None);
        assert_eq!(extract_pane_id("terminal_\n"), None);
    }

    #[test]
    fn splits_pane_ids() {
        assert_eq!(split_pane_id("terminal_42").unwrap(), (false, 42));
        assert_eq!(split_pane_id("plugin_0").unwrap(), (true, 0));
        assert!(split_pane_id("42").is_err());
        assert!(split_pane_id("terminal_x").is_err());
    }
}
