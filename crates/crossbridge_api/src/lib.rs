//! Insulation layer between the synchronous orchestrator core and crossbridge's
//! async library crates (REQ-20b).
//!
//! # What this crate is
//!
//! `crossbridge_api` owns **all** crossbridge I/O and is the **only** workspace
//! crate permitted to depend on `tokio`/`tokio-util` or on any `crossbridge-*`
//! crate. Two boundaries meet here and both are load-bearing:
//!
//! - **The sync/async membrane.** The orchestrator core is a single-threaded,
//!   synchronous, tokio-free poll loop. crossbridge's server is `async`. The
//!   membrane is [`serve`], which drives `crossbridge_server::run` on a
//!   dedicated OS thread with a `new_current_thread` runtime ([`ServerHandle`]),
//!   so the core never blocks on async. One-shot work — answering a peer — is
//!   synchronous ([`answer`]) and needs no runtime at all.
//! - **The trust boundary.** crossbridge speaks to *untrusted* peers over Unix
//!   sockets. All crossbridge I/O is orchestrator-side, outside any worker bwrap
//!   sandbox (the socket root is never mounted into a worker). This crate's
//!   public signatures carry only vetinari-owned plain types — issue id `i64`,
//!   slug `String`, comment text `String`, `PathBuf` — and the self-contained
//!   [`CrossbridgeError`]. No `crosslink` or `crossbridge` type crosses the
//!   surface; `crosslink_api` remains the sole namer of crosslink types.
//!
//! # Skeleton status (disabled by default)
//!
//! [`serve`] and [`answer`] are real and wired to crossbridge, but the
//! orchestrator does **not** call [`serve`] during normal operation yet: no
//! server is started, no socket opened, and the fixture dogfood is unaffected.
//! Wiring `serve()` into the pump — and the inbound-ingestion / answer-back
//! state machine around [`answer`] — is a later step. This crate exists so that
//! step is a wiring change against a stable surface, not a fresh implementation.
//!
//! # Surface
//!
//! - [`serve`] / [`ServeCfg`] / [`ServerHandle`] — the embedded server.
//! - [`answer`] / [`AnswerReq`] / [`AnswerComment`] / [`AnswerOutcome`] — one
//!   `SubmitAnswer` wire round-trip.
//! - [`own_slug`] — crossbridge's own slug derivation.
//! - [`labels`] — the `xb*` marker label strings as plain consts.
//! - [`CrossbridgeError`] — the self-contained error type.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod answer;
mod error;
pub mod labels;
mod serve;
mod slug;

pub use answer::{answer, AnswerComment, AnswerOutcome, AnswerReq};
pub use error::{CrossbridgeError, Result};
pub use serve::{serve, ServeCfg, ServerHandle};
pub use slug::own_slug;
