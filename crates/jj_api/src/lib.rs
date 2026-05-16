//! Insulation layer between the orchestrator and `jj-lib` (REQ-1c).
//!
//! The orchestrator never links `jj-lib` directly. It depends only on the
//! stable adapter surface in this crate: the [`JjWorkspace`] handle and its
//! methods, plus the self-contained [`JjError`] type. When `jj-lib`'s API
//! churns, the fix is localized here.
//!
//! `jj-lib` is async-heavy; this crate drives those futures to completion on
//! the calling thread (via `pollster`) so every adapter method is synchronous.
//! No tokio runtime is pulled into the orchestrator binary (REQ-1a).
//!
//! # Operations
//!
//! Each operation the orchestrator performs is a method on [`JjWorkspace`]:
//! workspace load, `log`, `status`, `diff`, `describe`, bookmark create / move
//! / list, `rebase`, workspace add / forget / list, and `git_push`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod error;
mod log;
mod revset;
mod workspace;

pub use error::{JjError, Result};
pub use log::CommitInfo;
pub use workspace::JjWorkspace;
