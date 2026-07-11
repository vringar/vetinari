//! vetinari orchestrator — library surface.
//!
//! The orchestrator ships as a binary (`src/main.rs`), but its phases are
//! built as modules behind this library crate so the integration tests under
//! `tests/` can drive them directly. Issue #2 (F2) lands the first two:
//!
//! - [`state`] — the SQLite-backed `state.db`, the orchestrator's
//!   authoritative state (REQ-2, REQ-2a, REQ-3b).
//! - [`recovery`] — the crash-safe resumption scaffold (REQ-15); the full
//!   deterministic table lands in P2 (#16).
//! - [`workspace`] — the per-worker jj workspace lifecycle behind the
//!   serializing `.jj/` gate (REQ-5a, REQ-12).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod recovery;
pub mod state;
pub mod workspace;
