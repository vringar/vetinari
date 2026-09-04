//! The embedded crossbridge server, run on a dedicated OS thread (spec §1.1,
//! review B1).
//!
//! # The sync/async membrane
//!
//! The orchestrator core is a single-threaded, synchronous, tokio-free poll
//! loop. crossbridge's server is `async` and needs a tokio runtime. This module
//! is the membrane between the two: [`serve`] spawns a **dedicated OS thread**
//! that owns a `new_current_thread` tokio runtime and drives
//! `crossbridge_server::run` to completion on it. The orchestrator core never
//! constructs a runtime, never `block_on`s, and never touches an async type —
//! it holds only a [`ServerHandle`] of plain methods.
//!
//! # Shutdown (cooperative best-effort, then bounded detach)
//!
//! `crossbridge_server::run` installs no signal handler and never calls
//! `process::exit`; the caller owns process lifetime (settled fact; review
//! B1a). [`serve`] therefore creates a `CancellationToken`, hands it to `run`,
//! and stores it in the [`ServerHandle`]. [`ServerHandle::shutdown`] cancels
//! the token; **when** `run` is sitting at its `biased` select, that select
//! takes the cancelled branch, drops all peer listeners, and returns `Ok(())`.
//!
//! But cancellation is only **cooperative**, and shutdown here is **not**
//! guaranteed to return cleanly. The pinned upstream `run` handles an accepted
//! connection *inline* in its `select!`, and `handler::handle_connection` does
//! `read_message(stream).await` on an **untrusted peer** with no read timeout
//! (`.crossbridge-src/crossbridge-server/src/handler.rs`). While the thread is
//! parked in that read, nothing polls the `shutdown.cancelled()` branch, so the
//! cancel is a no-op and the server thread does not stop. The real fix is an
//! upstream read timeout in `handle_connection`; this crate is the *embedder*
//! and cannot patch upstream, so it defends the pump instead.
//!
//! The contract is therefore: **cancel the token, wait a bounded
//! [`SHUTDOWN_JOIN_TIMEOUT`], and if the thread has not unwound by the
//! deadline, detach it** — drop the [`JoinHandle`] and surface
//! [`CrossbridgeError::ShutdownTimedOut`] — rather than block the caller. A
//! leaked-but-parked OS thread is strictly better than a permanently hung
//! orchestrator pump. [`ServerHandle::join`] and `Drop` both honor this bound
//! and never block beyond the deadline.
//!
//! # Signals
//!
//! Because the runtime here does **not** enable tokio's `signal` feature, this
//! thread installs no competing signal disposition — process-level signal
//! handling (SIGINT/SIGTERM) stays with the orchestrator's main thread, which
//! is what should drive shutdown. True pthread-level signal *masking* on this
//! thread requires `libc`/`unsafe`, which this crate forbids
//! (`#![forbid(unsafe_code)]`); it belongs at the orchestrator level when the
//! pump wires `serve()` in step 4, and is unnecessary in the meantime because
//! the orchestrator does not start a server during normal operation (this is a
//! disabled-by-default skeleton — no `serve()` call, no socket opened).
//!
//! # Trust boundary
//!
//! All crossbridge I/O is orchestrator-side, outside any worker bwrap sandbox
//! (the socket root is never mounted into a worker). [`ServeCfg`] carries only
//! vetinari-owned plain types; the mapping to `crossbridge_server::ServerConfig`
//! is confined to [`ServeCfg::into_server_config`].

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use crossbridge_server::paths::SocketLayout;
use crossbridge_server::run::{run, ServerConfig};
use tokio_util::sync::CancellationToken;

use crate::error::{CrossbridgeError, Result};

/// How long [`ServerHandle`] shutdown waits for the server thread to unwind
/// before detaching it (see the module "Shutdown" docs). The wait is bounded
/// because the upstream handler may be parked in an untrusted-peer read with no
/// timeout, where cooperative cancellation can never land — blocking on that
/// would hang the orchestrator pump.
const SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for the embedded server, in vetinari-owned plain types.
///
/// This is the plain-typed mirror of `crossbridge_server::ServerConfig`; the
/// orchestrator populates it from its own config without linking crossbridge.
#[derive(Debug, Clone)]
pub struct ServeCfg {
    /// This node's crossbridge slug (see [`crate::own_slug`]).
    pub slug: String,
    /// The peer group this node registers into.
    pub group: String,
    /// Repository root — the directory that contains `.crosslink/`.
    pub repo_root: PathBuf,
    /// crossbridge runtime root (the supervisor register socket and per-peer
    /// listener sockets live under it). Plain path; no crossbridge type.
    pub socket_root: PathBuf,
}

impl ServeCfg {
    /// Map to crossbridge's `ServerConfig`. The only place a `ServerConfig` or
    /// `SocketLayout` is named.
    fn into_server_config(self) -> ServerConfig {
        ServerConfig {
            slug: self.slug,
            group: self.group,
            repo_path: self.repo_root,
            layout: SocketLayout::new(self.socket_root),
        }
    }
}

/// A running (or finished) embedded crossbridge server.
///
/// Owns the dedicated server thread and its shutdown token. Dropping the handle
/// requests shutdown and joins the thread with a bounded deadline
/// ([`SHUTDOWN_JOIN_TIMEOUT`]); if the thread does not unwind in time it is
/// **detached** rather than joined, so `Drop` never blocks the caller (see the
/// module "Shutdown" docs for why the join must be bounded).
#[derive(Debug)]
pub struct ServerHandle {
    /// Cancelled to ask `crossbridge_server::run` to shut down cleanly.
    shutdown: CancellationToken,
    /// The dedicated OS thread; its result is `run`'s outcome, mapped to a
    /// plain-typed [`Result`]. `Option` so [`ServerHandle::join`] and `Drop`
    /// can take it without leaving a dangling handle.
    thread: Option<JoinHandle<Result<()>>>,
    /// Completion signal for a bounded join. The server thread holds the paired
    /// `Sender`, which is dropped when its body unwinds (normally *or* by
    /// panic); a `recv_timeout` on this end therefore returns `Disconnected`
    /// the moment the thread has finished, and `Timeout` if it is still parked.
    /// It carries no value — the real result/panic payload comes from
    /// [`JoinHandle::join`], which is non-blocking once the signal has fired.
    done: Receiver<()>,
}

impl ServerHandle {
    /// Request a clean shutdown of the embedded server.
    ///
    /// Cancels the token `crossbridge_server::run` selects on; idempotent and
    /// non-blocking. Call [`ServerHandle::join`] afterwards to wait for the
    /// thread to unwind and surface `run`'s result.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    /// `true` once the server thread has finished (cleanly or with an error).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(JoinHandle::is_finished)
    }

    /// Request shutdown, then wait — **bounded** — for the server thread and
    /// surface its result.
    ///
    /// Waits at most [`SHUTDOWN_JOIN_TIMEOUT`]. If the thread does not unwind by
    /// then (e.g. it is parked in an untrusted-peer read that cooperative
    /// cancellation cannot reach — see the module "Shutdown" docs), the thread
    /// is **detached** and this returns [`CrossbridgeError::ShutdownTimedOut`]
    /// rather than block the caller forever.
    ///
    /// # Errors
    /// - [`CrossbridgeError::ServerExited`] if `crossbridge_server::run` returned
    ///   an error;
    /// - [`CrossbridgeError::ServerPanicked`] if the thread panicked;
    /// - [`CrossbridgeError::ShutdownTimedOut`] if the thread was still parked at
    ///   the deadline and had to be detached.
    pub fn join(mut self) -> Result<()> {
        self.shutdown.cancel();
        Self::join_thread_bounded(self.thread.take(), &self.done, SHUTDOWN_JOIN_TIMEOUT)
    }

    /// Join the (optional) thread handle with a deadline, flattening the
    /// panic/exit/timeout cases.
    ///
    /// The wait is on `done`: the server thread's `Sender` is dropped exactly
    /// when its body unwinds, so `recv_timeout` returning `Disconnected` means
    /// the thread has finished and [`JoinHandle::join`] is now non-blocking
    /// (yielding the real result or the panic payload). A `Timeout` means the
    /// thread is still parked; we **detach** it — drop the `JoinHandle`, leaking
    /// the OS thread — rather than block, which is the whole point of the bound.
    fn join_thread_bounded(
        thread: Option<JoinHandle<Result<()>>>,
        done: &Receiver<()>,
        timeout: Duration,
    ) -> Result<()> {
        let Some(thread) = thread else {
            return Ok(());
        };
        match done.recv_timeout(timeout) {
            // The deadline elapsed with the thread still parked: detach it
            // (drop the handle) so we never block the pump.
            Err(RecvTimeoutError::Timeout) => {
                drop(thread);
                Err(CrossbridgeError::ShutdownTimedOut { after: timeout })
            }
            // `Disconnected` (body unwound) — or the impossible `Ok(())`, since
            // nothing is ever sent. Either way the thread has finished, so
            // `join` returns promptly with the result or the panic payload.
            Err(RecvTimeoutError::Disconnected) | Ok(()) => match thread.join() {
                Ok(run_result) => run_result,
                Err(payload) => Err(CrossbridgeError::ServerPanicked {
                    detail: panic_detail(&payload),
                }),
            },
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        // Request shutdown and join with the same bound as `join`: never block
        // the caller beyond the deadline. On timeout the thread is detached
        // (leaked) — a parked thread is strictly better than a hung pump.
        self.shutdown.cancel();
        match Self::join_thread_bounded(self.thread.take(), &self.done, SHUTDOWN_JOIN_TIMEOUT) {
            Ok(()) => {}
            Err(CrossbridgeError::ShutdownTimedOut { after }) => {
                tracing::warn!(
                    ?after,
                    "embedded crossbridge server did not stop within the bounded deadline; detaching the thread"
                );
            }
            Err(e) => {
                tracing::warn!(error = ?e, "embedded crossbridge server exited with an error on drop");
            }
        }
    }
}

/// Best-effort human-readable description of a thread panic payload.
fn panic_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Start the embedded crossbridge server on a dedicated OS thread.
///
/// Spawns a thread that builds a `new_current_thread` tokio runtime and drives
/// `crossbridge_server::run(cfg, shutdown)` on it until the returned
/// [`ServerHandle`] is shut down (or dropped). The call returns as soon as the
/// thread is spawned; it does **not** block on the async server.
///
/// The orchestrator does not call this during normal operation yet — wiring
/// `serve()` into the pump is step 4. It exists, compiles, and is real so that
/// step is a wiring change, not a new implementation.
///
/// # Errors
/// Returns [`CrossbridgeError::RuntimeStart`] if the server thread cannot be
/// spawned. Errors from `run` itself surface later via [`ServerHandle::join`].
pub fn serve(cfg: ServeCfg) -> Result<ServerHandle> {
    let server_config = cfg.into_server_config();
    let shutdown = CancellationToken::new();
    let thread_token = shutdown.clone();
    // Completion signal for the bounded join: the thread holds `done_tx` and
    // drops it as its body unwinds (normally or by panic), which disconnects
    // `done` and lets shutdown's `recv_timeout` distinguish "finished" from
    // "still parked". See [`ServerHandle::join_thread_bounded`].
    let (done_tx, done) = std::sync::mpsc::channel::<()>();

    let thread = std::thread::Builder::new()
        .name("crossbridge-server".to_owned())
        .spawn(move || -> Result<()> {
            // Held for the whole life of this thread; dropped as the body
            // unwinds to signal completion to a bounded join.
            let _completion = done_tx;
            // A current-thread runtime: no worker-thread pool, no tokio signal
            // handler. The whole async server lives on this one OS thread.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| CrossbridgeError::RuntimeStart {
                    source: Box::new(source),
                })?;
            runtime
                .block_on(run(server_config, thread_token))
                // `run` yields `anyhow::Result<()>`; `anyhow::Error` converts
                // straight into our boxed cause without this crate naming
                // `anyhow` anywhere (the type flows through from `run`).
                .map_err(|source| CrossbridgeError::ServerExited {
                    source: source.into(),
                })
        })
        .map_err(|source| CrossbridgeError::RuntimeStart {
            source: Box::new(source),
        })?;

    Ok(ServerHandle {
        shutdown,
        thread: Some(thread),
        done,
    })
}

/// The crossbridge default socket root, for when the orchestrator config leaves
/// [`ServeCfg::socket_root`] unset.
///
/// Resolves crossbridge's own precedence — `$CROSSBRIDGE_SOCKET_ROOT` >
/// `$XDG_RUNTIME_DIR/crossbridge` > the compiled-in `/run/crossbridge` — via
/// `crossbridge_protocol::default_socket_root`, returning a plain [`PathBuf`] so
/// the orchestrator never has to name crossbridge's socket-layout policy itself
/// (a divergent reimplementation would desync us from our peers, the same
/// hazard [`crate::own_slug`] guards against, review N7). This is exactly what
/// the crossbridge binaries do when no `--runtime-root` flag is passed.
#[must_use]
pub fn default_socket_root() -> PathBuf {
    crossbridge_protocol::default_socket_root(|key| std::env::var_os(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_cfg_maps_to_server_config() {
        let cfg = ServeCfg {
            slug: "tools".to_owned(),
            group: "reversing".to_owned(),
            repo_root: PathBuf::from("/repo"),
            socket_root: PathBuf::from("/run/xb"),
        };
        let sc = cfg.into_server_config();
        assert_eq!(sc.slug, "tools");
        assert_eq!(sc.group, "reversing");
        assert_eq!(sc.repo_path, PathBuf::from("/repo"));
        // ServerConfig::db_path is derived from repo_path — proves the mapping.
        assert_eq!(sc.db_path(), PathBuf::from("/repo/.crosslink/issues.db"));
        assert_eq!(
            sc.layout.register_socket(),
            PathBuf::from("/run/xb/register.socket")
        );
    }

    /// Real end-to-end wiring, no socket/supervisor needed: a repo with no
    /// crosslink DB makes `run` return an error immediately (its first check),
    /// which must propagate through the thread + runtime + join as
    /// `ServerExited`. Exercises the whole membrane without binding a socket.
    #[test]
    fn serve_surfaces_missing_db_as_server_exited() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = ServeCfg {
            slug: "tools".to_owned(),
            group: "reversing".to_owned(),
            repo_root: tmp.path().to_path_buf(), // no .crosslink/issues.db
            socket_root: tmp.path().join("run"),
        };
        let handle = serve(cfg).expect("thread spawns");
        let err = handle
            .join()
            .expect_err("run must fail without a crosslink DB");
        assert!(matches!(err, CrossbridgeError::ServerExited { .. }));
    }

    /// Real shutdown-token lifecycle, no bound socket: with a valid (empty)
    /// crosslink DB present, `run` gets past its DB check and into its select
    /// loop, retrying to reach a (nonexistent) supervisor register socket. The
    /// `biased` select must take the cancelled branch when we shut down, and
    /// `join` must then return `Ok(())`. No listener socket is ever bound
    /// (registration never succeeds), so this needs no live peer/supervisor.
    #[test]
    fn serve_shuts_down_cleanly_via_token() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let crosslink_dir = tmp.path().join(".crosslink");
        std::fs::create_dir_all(&crosslink_dir).expect("create .crosslink dir");
        // Build a real, empty crosslink DB so `run` proceeds past its DB check.
        let _db = crosslink::db::Database::open(&crosslink_dir.join("issues.db"))
            .expect("open crosslink db");

        let cfg = ServeCfg {
            slug: "tools".to_owned(),
            group: "reversing".to_owned(),
            repo_root: tmp.path().to_path_buf(),
            // A socket root with no register.socket: registration backs off and
            // retries; cancellation must still win promptly.
            socket_root: tmp.path().join("run"),
        };
        let handle = serve(cfg).expect("thread spawns");
        handle.shutdown();
        handle.join().expect("clean shutdown returns Ok");
    }

    /// The load-bearing bound: a server thread that will **not** stop promptly
    /// (simulating the upstream handler parked in an untrusted-peer read that
    /// cooperative cancellation cannot reach) must not hang the caller. The
    /// bounded join must return `ShutdownTimedOut` within roughly the deadline
    /// and detach the thread rather than block. Exercises the timed-join
    /// mechanism directly, without needing a socket, peer, or supervisor.
    #[test]
    fn bounded_join_detaches_a_wedged_thread_instead_of_hanging() {
        use std::time::Instant;

        let (done_tx, done) = std::sync::mpsc::channel::<()>();
        // A thread that parks far longer than the test's deadline while holding
        // the completion sender, so `done` never disconnects in time.
        let wedged = std::thread::spawn(move || -> Result<()> {
            let _completion = done_tx;
            std::thread::sleep(Duration::from_secs(60));
            Ok(())
        });

        let deadline = Duration::from_millis(200);
        let start = Instant::now();
        let result = ServerHandle::join_thread_bounded(Some(wedged), &done, deadline);
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(CrossbridgeError::ShutdownTimedOut { after }) if after == deadline),
            "wedged thread must surface ShutdownTimedOut, got {result:?}"
        );
        // Must return near the deadline, nowhere near the thread's 60s sleep.
        assert!(
            elapsed < Duration::from_secs(5),
            "bounded join must not block on the wedged thread (took {elapsed:?})"
        );
        // The detached thread is intentionally leaked; the test process exits.
    }

    /// The default-socket-root wrapper returns a non-empty path whose final
    /// component reflects crossbridge's precedence (`…/crossbridge` when derived
    /// from an env root, or the compiled-in fallback). The precedence itself is
    /// exhaustively tested upstream in `crossbridge_protocol`; this only guards
    /// that our thin wrapper wires the real global env lookup through.
    #[test]
    fn default_socket_root_is_a_nonempty_path() {
        let root = default_socket_root();
        assert!(
            !root.as_os_str().is_empty(),
            "default socket root must never be empty, got {root:?}"
        );
        // Either the compiled-in fallback, or an env-derived `<root>/crossbridge`.
        assert!(
            root.as_path() == std::path::Path::new("/run/crossbridge")
                || root.file_name().is_some_and(|c| c == "crossbridge")
                || std::env::var_os("CROSSBRIDGE_SOCKET_ROOT").is_some(),
            "unexpected default socket root shape: {root:?}"
        );
    }

    /// The fast path: a thread that finishes on its own is joined promptly and
    /// its result surfaces — the bound does not corrupt the normal case.
    #[test]
    fn bounded_join_surfaces_result_of_a_finished_thread() {
        let (done_tx, done) = std::sync::mpsc::channel::<()>();
        let finished = std::thread::spawn(move || -> Result<()> {
            let _completion = done_tx;
            Ok(())
        });
        ServerHandle::join_thread_bounded(Some(finished), &done, Duration::from_secs(5))
            .expect("a cleanly finished thread joins Ok within the bound");
    }
}
