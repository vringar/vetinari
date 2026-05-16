//! Error type for the jj_api adapter (REQ-1b, REQ-1c).
//!
//! [`JjError`] is deliberately *self-contained*: every variant carries the
//! underlying `jj-lib` failure as a boxed [`std::error::Error`] rather than a
//! concrete `jj-lib` type. That keeps `jj-lib`'s error-enum churn from leaking
//! into the orchestrator — callers match on `JjError`'s own variants, and the
//! orchestrator wraps `JjError` at its phase boundaries.
//!
//! Every variant implements [`miette::Diagnostic`] with a stable `code(...)` so
//! failures render as compiler-style reports in `events.jsonl`.

use std::path::PathBuf;

use miette::Diagnostic;
use thiserror::Error;

/// Boxed underlying cause. The concrete `jj-lib` error type is intentionally
/// erased so it cannot appear in this crate's public signatures.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Failure of a jj_api adapter operation.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum JjError {
    /// The jj workspace at `path` could not be loaded.
    #[error("failed to load jj workspace at `{path}`")]
    #[diagnostic(
        code(vetinari::jj::workspace_load),
        help("Confirm the path is inside a jj repository (a `.jj/` directory is present).")
    )]
    WorkspaceLoad {
        /// Path the adapter was asked to load.
        path: PathBuf,
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// The repository view could not be loaded at its head operation.
    #[error("failed to load the jj repository at its head operation")]
    #[diagnostic(
        code(vetinari::jj::repo_load),
        help("The operation log may be corrupt; inspect with `jj op log`.")
    )]
    RepoLoad {
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// Constructing jj user settings from configuration failed.
    #[error("failed to build jj user settings")]
    #[diagnostic(code(vetinari::jj::settings))]
    Settings {
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// A revset expression could not be parsed, resolved, or evaluated.
    #[error("invalid revset `{revset}`")]
    #[diagnostic(
        code(vetinari::jj::revset),
        help("Check the revset syntax — see `jj help -k revsets`.")
    )]
    Revset {
        /// The offending revset string.
        revset: String,
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// A revset resolved to no commit where exactly one was required.
    #[error("revset `{revset}` matched no commit")]
    #[diagnostic(
        code(vetinari::jj::no_such_revision),
        help("Check the revision id or bookmark name.")
    )]
    NoSuchRevision {
        /// The revset that matched nothing.
        revset: String,
    },

    /// A revset matched more than one commit where exactly one was required.
    #[error("revset `{revset}` matched {count} commits, expected exactly one")]
    #[diagnostic(
        code(vetinari::jj::ambiguous_revision),
        help("Narrow the revset so it identifies a single commit.")
    )]
    AmbiguousRevision {
        /// The ambiguous revset string.
        revset: String,
        /// How many commits it matched.
        count: usize,
    },

    /// A backend object read or write failed.
    #[error("jj backend operation failed")]
    #[diagnostic(code(vetinari::jj::backend))]
    Backend {
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// Committing a transaction failed.
    #[error("failed to commit jj transaction for `{operation}`")]
    #[diagnostic(
        code(vetinari::jj::transaction),
        help("The operation log was not advanced; the repository is unchanged.")
    )]
    Transaction {
        /// Human-readable name of the attempted operation.
        operation: String,
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// Snapshotting the working copy failed.
    #[error("failed to snapshot the working copy")]
    #[diagnostic(code(vetinari::jj::snapshot))]
    Snapshot {
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// Rendering a diff as patch text failed.
    #[error("failed to render diff as patch text")]
    #[diagnostic(code(vetinari::jj::diff))]
    Diff {
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// A bookmark could not be created because the name is already taken.
    #[error("bookmark `{name}` already exists")]
    #[diagnostic(
        code(vetinari::jj::bookmark_exists),
        help("Use `bookmark_move` to repoint an existing bookmark.")
    )]
    BookmarkExists {
        /// The bookmark name that collided.
        name: String,
    },

    /// A required bookmark does not exist.
    #[error("bookmark `{name}` does not exist")]
    #[diagnostic(code(vetinari::jj::bookmark_missing))]
    BookmarkMissing {
        /// The bookmark name that was looked up.
        name: String,
    },

    /// Adding a workspace failed.
    #[error("failed to add jj workspace at `{path}`")]
    #[diagnostic(code(vetinari::jj::workspace_add))]
    WorkspaceAdd {
        /// Intended workspace root.
        path: PathBuf,
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// Forgetting a workspace failed.
    #[error("failed to forget jj workspace `{name}`")]
    #[diagnostic(code(vetinari::jj::workspace_forget))]
    WorkspaceForget {
        /// Name of the workspace being forgotten.
        name: String,
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// A git push failed outright (transport or remote error).
    #[error("git push to `{remote}` failed")]
    #[diagnostic(code(vetinari::jj::push_failed))]
    PushFailed {
        /// Remote name the push targeted.
        remote: String,
        /// Underlying `jj-lib` cause.
        #[source]
        source: BoxError,
    },

    /// A git push completed but the remote rejected one or more refs.
    #[error("git push to `{remote}` rejected: {summary}")]
    #[diagnostic(
        code(vetinari::jj::push_rejected),
        help("The remote diverged; fetch and rebase before retrying.")
    )]
    PushRejected {
        /// Remote name the push targeted.
        remote: String,
        /// One-line summary of which refs were rejected and why.
        summary: String,
    },
}

/// Convenience `Result` alias for adapter operations.
pub type Result<T, E = JjError> = std::result::Result<T, E>;
