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
//! - [`artifacts`] — the worker → orchestrator artifact contract, the DONE
//!   sentinel gate, and idempotent translation planning (REQ-3, REQ-3b).
//! - [`events`] — the append-only `events.jsonl` writer and the heartbeat
//!   reader / staleness check (REQ-14, AC-9, AC-14).
//! - [`spawn`] — hosting a worker in a zellij pane inside a prepared jj
//!   workspace, behind the per-role mount matrix and the `claude-sandbox`
//!   version-pin guard (REQ-1d, REQ-4, REQ-4a, REQ-5, REQ-13, AC-19, AC-27).
//! - [`qa`] — the static QA gate: runs `.orchestrator/static_qa.sh` against a
//!   worker's workspace and derives a deterministic, exit-code-owned pass/fail
//!   verdict (REQ-9, REQ-9a, AC-7).
//! - [`landing`] — local-mode landing: rebases a converged issue's change onto
//!   `main` and fast-forwards the `main` bookmark, driving a resumable substate
//!   machine through the `.jj/` gate (REQ-17 local path, REQ-2a, AC-11a, AC-18).
//! - [`config`] — the `.orchestrator/config.toml` parser: the concurrency
//!   budget, poll cadence, timeouts, and dogfood worker command (REQ-13).
//! - [`pump`] — the build pump: the integration keystone that drives one
//!   `phase:graphed` issue through implement → QA → land → `phase:merged`,
//!   headless (REQ-16, REQ-13, AC-11a).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod artifacts;
pub mod config;
pub mod events;
pub mod landing;
pub mod pump;
pub mod qa;
pub mod recovery;
pub mod spawn;
pub mod state;
pub mod workspace;
