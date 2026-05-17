//! Insulation layer between the orchestrator and the `crosslink` crate
//! (REQ-3a).
//!
//! The orchestrator never links `crosslink` directly. It depends only on the
//! stable adapter surface in this crate: the [`CrosslinkRepo`] handle and its
//! methods, the [`IssueInfo`] data type, and the self-contained
//! [`CrosslinkError`]. When crosslink's library API churns — and it carries no
//! stability promise — the fix is localized here.
//!
//! crosslink's library API is synchronous, so every adapter method is too.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod error;
mod repo;

pub use error::{CrosslinkError, Result};
pub use repo::{CrosslinkRepo, IssueInfo};
