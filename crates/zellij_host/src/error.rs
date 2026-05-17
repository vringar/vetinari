//! Error type for the zellij_host adapter (REQ-1b, REQ-1d).
//!
//! Every variant implements [`miette::Diagnostic`] with a stable `code(...)`,
//! so a worker-hosting failure renders as a compiler-style report.

use miette::Diagnostic;
use thiserror::Error;

/// Failure of a zellij_host operation.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum ZellijError {
    /// The `zellij` binary could not be executed at all.
    #[error("could not execute the `zellij` binary")]
    #[diagnostic(
        code(vetinari::zellij::unavailable),
        help("Ensure `zellij` is on PATH — run inside the nix dev shell (`nix-shell`).")
    )]
    ZellijUnavailable {
        /// The underlying spawn error.
        #[source]
        source: std::io::Error,
    },

    /// A `zellij` invocation exited non-zero.
    #[error("`{command}` failed ({})", describe_exit(*exit_code))]
    #[diagnostic(
        code(vetinari::zellij::command_failed),
        help("zellij's own stderr is preserved above; check the session is alive.")
    )]
    CommandFailed {
        /// The `zellij` command line that failed (for diagnostics).
        command: String,
        /// Process exit code, or `None` if the process was killed by a signal.
        exit_code: Option<i32>,
        /// Trimmed stderr from the failed invocation.
        stderr: String,
    },

    /// `zellij`'s output could not be parsed into the expected shape.
    #[error("could not parse `zellij` output for {operation}: {detail}")]
    #[diagnostic(code(vetinari::zellij::output_parse))]
    OutputParse {
        /// The adapter operation whose output failed to parse.
        operation: String,
        /// What specifically went wrong.
        detail: String,
    },

    /// [`crate::pane_create`] was given an empty command.
    #[error("pane_create requires a non-empty command (program plus arguments)")]
    #[diagnostic(code(vetinari::zellij::empty_command))]
    EmptyCommand,
}

/// Render an exit code for [`ZellijError::CommandFailed`]'s message.
fn describe_exit(exit_code: Option<i32>) -> String {
    match exit_code {
        Some(code) => format!("exit {code}"),
        None => "killed by signal".to_owned(),
    }
}

/// Convenience `Result` alias for adapter operations.
pub type Result<T, E = ZellijError> = std::result::Result<T, E>;
