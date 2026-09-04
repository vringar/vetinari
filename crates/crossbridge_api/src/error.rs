//! Error type for the crossbridge_api adapter (REQ-20b).
//!
//! crossbridge's library API is `anyhow`-based and its wire helpers surface a
//! `crossbridge_protocol::Error`; this adapter carries either underlying
//! failure as a boxed [`std::error::Error`] and adds its own structured,
//! [`miette::Diagnostic`] variants on top. As with `crosslink_api`'s
//! `CrosslinkError`, the concrete crossbridge/`anyhow` types never appear in
//! this crate's public API — the orchestrator branches on adapter conditions
//! without string-matching or linking crossbridge.

use std::path::PathBuf;

use miette::Diagnostic;
use thiserror::Error;

/// Boxed underlying cause. crossbridge's `anyhow::Error`s and
/// `crossbridge_protocol::Error`s convert into this; the concrete type never
/// appears in this crate's public API.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Failure of a crossbridge_api adapter operation.
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum CrossbridgeError {
    /// The dedicated server-thread runtime could not be created.
    #[error("failed to start the crossbridge server runtime")]
    #[diagnostic(code(vetinari::crossbridge::runtime_start))]
    RuntimeStart {
        /// Underlying cause (tokio runtime build / thread spawn failure).
        #[source]
        source: BoxError,
    },

    /// The embedded server exited with an error rather than a clean shutdown.
    ///
    /// Surfaced from [`crate::ServerHandle::join`]: the server thread ran
    /// `crossbridge_server::run` to completion and it returned an error (for
    /// example, the crosslink DB was missing, or the supervisor session failed
    /// fatally before shutdown was requested).
    #[error("the embedded crossbridge server exited with an error")]
    #[diagnostic(code(vetinari::crossbridge::server_exited))]
    ServerExited {
        /// Underlying `crossbridge_server::run` cause.
        #[source]
        source: BoxError,
    },

    /// The server thread panicked; its join could not produce a result.
    #[error("the crossbridge server thread panicked")]
    #[diagnostic(code(vetinari::crossbridge::server_panicked))]
    ServerPanicked {
        /// Best-effort description of the panic payload.
        detail: String,
    },

    /// Shutdown was requested but the server thread did not unwind within the
    /// bounded join deadline, so it was **detached** (leaked) rather than block
    /// the caller.
    ///
    /// Surfaced from [`crate::ServerHandle::join`]. This is the deliberate
    /// escape hatch for the upstream inline-handler design: `crossbridge_server`
    /// can be parked in an untrusted-peer read with no timeout, where
    /// cooperative cancellation cannot land (see [`crate::serve`]'s module
    /// docs). A leaked-but-parked OS thread is strictly better than a hung
    /// orchestrator pump.
    #[error("the crossbridge server thread did not stop within {after:?}; it was detached")]
    #[diagnostic(
        code(vetinari::crossbridge::shutdown_timed_out),
        help("The server thread was parked (likely in an untrusted-peer read) and was leaked to keep the pump live. The upstream read-timeout fix is the real remedy.")
    )]
    ShutdownTimedOut {
        /// The bounded join deadline that elapsed before detaching.
        after: std::time::Duration,
    },

    /// The target peer's socket could not be reached for a `SubmitAnswer`
    /// round-trip.
    ///
    /// This is the degraded-but-not-terminal condition the answer state machine
    /// maps to `answer_unreachable` (spec §1.3): the source peer is offline.
    /// The orchestrator retries, bounded, on later poll ticks.
    #[error("crossbridge peer `{peer}` is unreachable at `{socket}`")]
    #[diagnostic(
        code(vetinari::crossbridge::peer_unreachable),
        help("The peer's crossbridge server is not connected; the answer is retried on a later tick.")
    )]
    PeerUnreachable {
        /// Slug of the peer we tried to answer.
        peer: String,
        /// Per-peer socket path that could not be reached.
        socket: PathBuf,
        /// Underlying connect/io cause.
        #[source]
        source: BoxError,
    },

    /// The `SubmitAnswer` frame could not be written or its response read.
    #[error("crossbridge answer round-trip to `{peer}` failed")]
    #[diagnostic(code(vetinari::crossbridge::wire))]
    Wire {
        /// Slug of the peer we were answering.
        peer: String,
        /// Underlying framing/io cause.
        #[source]
        source: BoxError,
    },

    /// The peer's server accepted the connection but rejected the answer.
    #[error("crossbridge peer `{peer}` rejected the answer: {message}")]
    #[diagnostic(code(vetinari::crossbridge::peer_rejected))]
    PeerRejected {
        /// Slug of the peer we were answering.
        peer: String,
        /// The peer server's error message.
        message: String,
    },

    /// The server's own slug could not be derived from the repository.
    #[error("could not derive the crossbridge slug for `{repo_root}`")]
    #[diagnostic(
        code(vetinari::crossbridge::slug_derivation),
        help("Pass an explicit slug override, or configure an `origin` remote on the repository.")
    )]
    SlugDerivation {
        /// The repository root whose slug derivation failed.
        repo_root: PathBuf,
        /// Underlying crossbridge derivation cause.
        #[source]
        source: BoxError,
    },
}

/// Convenience `Result` alias for adapter operations.
pub type Result<T, E = CrossbridgeError> = std::result::Result<T, E>;
