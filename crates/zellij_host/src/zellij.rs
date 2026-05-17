//! The single point where this crate shells out to the `zellij` CLI.
//!
//! Driving zellij through its CLI is the deliberate, scoped exception to
//! REQ-1a documented in REQ-1d. Confining the `std::process::Command` use to
//! this one helper keeps every adapter operation a thin argument-builder.

use std::process::Command;

use crate::error::{Result, ZellijError};

/// Run `zellij` with `args`, returning its stdout on success.
///
/// A non-zero exit becomes [`ZellijError::CommandFailed`] carrying zellij's
/// stderr; a failure to spawn the binary at all becomes
/// [`ZellijError::ZellijUnavailable`].
pub(crate) fn run_zellij(args: &[&str]) -> Result<String> {
    let output = Command::new("zellij")
        .args(args)
        .output()
        .map_err(|source| ZellijError::ZellijUnavailable { source })?;
    if !output.status.success() {
        return Err(ZellijError::CommandFailed {
            command: format!("zellij {}", args.join(" ")),
            exit_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
