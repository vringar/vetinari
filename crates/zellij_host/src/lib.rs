//! Worker-host adapter (REQ-1d): hosts each orchestrator worker inside a named
//! pane of a long-lived headless `zellij` session.
//!
//! # Why the `zellij` CLI
//!
//! This crate drives zellij by shelling out to the `zellij` CLI rather than
//! linking `zellij-server`/`zellij-utils`. That is a deliberate, scoped
//! exception to REQ-1a's "don't shell out" principle — a feasibility spike of
//! zellij 0.44.2 found its server must run as a daemonized process regardless
//! of approach, it exposes no per-pane environment API, and its internal
//! crates carry no stability promise. The rationale is recorded in REQ-1d of
//! `.design/vdd-orchestrator.md`. The shell-out is confined to this crate; the
//! orchestrator core reaches zellij only through the adapter surface here, and
//! `crates/zellij_host` is the one crate the AC-24 no-shell-out lint skips.
//!
//! # Surface
//!
//! - [`session_ensure`] — create-or-attach the headless session.
//! - [`pane_create`] — open a named pane running a command.
//! - [`pane_alive`] — is a pane still open?
//! - [`pane_close`] — close a pane.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod error;
mod pane;
mod session;
mod zellij;

pub use error::{Result, ZellijError};
pub use pane::{pane_alive, pane_close, pane_create, PaneHandle};
pub use session::{session_ensure, SessionHandle};
