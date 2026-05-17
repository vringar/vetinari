//! Error type for the crosslink_api adapter (REQ-1b, REQ-3a).
//!
//! crosslink's library API is uniformly `anyhow`-based — it exposes no typed
//! error enum. This adapter therefore carries the underlying failure as a
//! boxed [`std::error::Error`] (an `anyhow::Error` converts straight into one)
//! and adds its own structured, [`miette::Diagnostic`] variants on top, so the
//! orchestrator can branch on adapter conditions without string-matching.

use std::path::PathBuf;

use miette::Diagnostic;
use thiserror::Error;

/// Boxed underlying cause. crosslink's `anyhow::Error`s convert into this; the
/// concrete crosslink/`anyhow` type never appears in this crate's public API.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Failure of a crosslink_api adapter operation.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum CrosslinkError {
    /// No `.crosslink/` directory could be found.
    #[error("no crosslink repository found (searched for a `.crosslink/` directory)")]
    #[diagnostic(
        code(vetinari::crosslink::not_a_repository),
        help("Run the orchestrator inside a crosslink-initialized repository.")
    )]
    NotARepository,

    /// The crosslink issue database could not be opened.
    #[error("failed to open the crosslink database at `{path}`")]
    #[diagnostic(code(vetinari::crosslink::database_open))]
    DatabaseOpen {
        /// Path of the `issues.db` that failed to open.
        path: PathBuf,
        /// Underlying crosslink cause.
        #[source]
        source: BoxError,
    },

    /// The requested issue does not exist.
    #[error("crosslink issue #{id} does not exist")]
    #[diagnostic(
        code(vetinari::crosslink::issue_not_found),
        help("Check the issue id; `crosslink issue list` shows what exists.")
    )]
    IssueNotFound {
        /// The issue id that was looked up.
        id: i64,
    },

    /// A read of crosslink data failed.
    #[error("crosslink read failed: {operation}")]
    #[diagnostic(code(vetinari::crosslink::read))]
    Read {
        /// Human-readable name of the read that failed.
        operation: String,
        /// Underlying crosslink cause.
        #[source]
        source: BoxError,
    },

    /// A write of crosslink data (comment or label) failed.
    #[error("crosslink write failed: {operation}")]
    #[diagnostic(code(vetinari::crosslink::write))]
    Write {
        /// Human-readable name of the write that failed.
        operation: String,
        /// Underlying crosslink cause.
        #[source]
        source: BoxError,
    },

    /// A comment was given a kind crosslink does not recognize.
    #[error("`{kind}` is not a recognized crosslink comment kind")]
    #[diagnostic(
        code(vetinari::crosslink::invalid_comment_kind),
        help("Valid kinds: note, plan, decision, observation, blocker, resolution, result, handoff, human, intervention, system.")
    )]
    InvalidCommentKind {
        /// The unrecognized kind string.
        kind: String,
    },

    /// The agent signing identity is missing or incompletely configured.
    #[error("crosslink signing identity unavailable: {detail}")]
    #[diagnostic(
        code(vetinari::crosslink::identity_unavailable),
        help("crosslink signs comments with an ssh key; configure the agent identity (`.crosslink/agent.json`).")
    )]
    IdentityUnavailable {
        /// What specifically is missing.
        detail: String,
    },

    /// Signing a payload failed.
    #[error("crosslink signing failed")]
    #[diagnostic(code(vetinari::crosslink::sign))]
    Sign {
        /// Underlying crosslink cause.
        #[source]
        source: BoxError,
    },
}

/// Convenience `Result` alias for adapter operations.
pub type Result<T, E = CrosslinkError> = std::result::Result<T, E>;
