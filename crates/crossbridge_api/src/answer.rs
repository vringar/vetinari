//! One `SubmitAnswer` wire round-trip (spec §1.3, REQ-20e/20g).
//!
//! When an inbound (`xb:inbound`) issue reaches a terminal phase, the
//! orchestrator sends its `--kind result` comments back to the originating peer
//! as a single `SubmitAnswer`. Only this wire round-trip lives in
//! `crossbridge_api`; gathering the result comments/labels is the orchestrator's
//! job through `crosslink_api` (review N2).
//!
//! The round-trip is deliberately **synchronous**: crossbridge's protocol
//! exposes blocking `write_message_sync`/`read_message_sync` framing helpers
//! over a `std::os::unix::net::UnixStream`, so a single answer needs no async
//! runtime at all. tokio stays reserved for the long-lived embedded server
//! ([`crate::serve`]); the answer path runs directly on the orchestrator's poll
//! thread without blocking on a runtime.
//!
//! All types crossing this boundary are vetinari-owned plain types (issue id
//! `i64`, slug `String`, comment text `String`, `PathBuf`). The connect-failed
//! case is reported as [`CrossbridgeError::PeerUnreachable`] — the degraded,
//! retryable `answer_unreachable` condition — distinct from a peer that
//! answered with a rejection ([`CrossbridgeError::PeerRejected`]).
//!
//! # Untrusted-peer defense
//!
//! Because this round-trip runs on the orchestrator's poll thread, a silent or
//! slow untrusted peer must never be able to stall it. Every blocking socket op
//! is bounded by [`ANSWER_IO_TIMEOUT`], set on the `UnixStream` immediately
//! after connect. An elapsed read/write deadline is operationally the same as
//! an offline peer, so it maps to the **retryable**
//! [`CrossbridgeError::PeerUnreachable`], not [`CrossbridgeError::Wire`].
//!
//! The real fix is an upstream read timeout in crossbridge's connection
//! handler; this crate is the embedder and defends the pump on our side. The
//! inbound frame is still capped at `crossbridge_protocol`'s 16 MiB
//! `MAX_FRAME_SIZE`, so a peer can force at most that allocation per round-trip
//! (bounded, not a memory-exhaustion hole) — the timeout, not the size cap, is
//! the load-bearing liveness fix; tightening the residual allocation cap is an
//! upstream follow-up.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crossbridge_protocol::{
    read_message_sync, write_message_sync, AnswerComment as WireComment, ClientRequest,
    Error as ProtocolError, ServerResponse, SubmitAnswer,
};

use crate::error::{CrossbridgeError, Result};

/// Read/write deadline for a single answer round-trip. Bounds every blocking
/// socket op so a silent or slow untrusted peer cannot stall the orchestrator's
/// synchronous poll thread. See the module "Untrusted-peer defense" docs.
const ANSWER_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A comment to carry back to the source peer, plain-typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerComment {
    /// crosslink comment kind (e.g. `"result"`).
    pub kind: String,
    /// The comment body, verbatim.
    pub content: String,
}

/// A request to answer one inbound crossbridge issue, plain-typed.
///
/// The orchestrator assembles this from the inbound issue's crosslink state:
/// `peer_slug`/`source_uuid` come from the issue's `xb-source:`/`xb-ref:`
/// labels, `own_slug` from [`crate::own_slug`], and `comments` from the issue's
/// `--kind result` comments read via `crosslink_api`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerReq {
    /// The originating peer's slug — the target of the answer.
    pub peer_slug: String,
    /// This node's own slug, used to locate our per-peer socket directory.
    pub own_slug: String,
    /// crossbridge runtime root (`<root>/<own_slug>/<peer_slug>.socket`).
    pub socket_root: PathBuf,
    /// Cross-node correlation id echoed back so the peer matches its outbound
    /// issue (the `xb-ref:` value).
    pub source_uuid: String,
    /// The result comments to deliver.
    pub comments: Vec<AnswerComment>,
}

/// Outcome of a successful `SubmitAnswer` round-trip, plain-typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerOutcome {
    /// The issue id the peer server reports for the answered issue.
    pub remote_issue_id: i64,
}

/// The per-peer socket path we connect to when answering `peer_slug`:
/// `<socket_root>/<own_slug>/<peer_slug>.socket`. Matches crossbridge-client's
/// `socket_dir(own).join("<peer>.socket")`.
fn answer_socket_path(req: &AnswerReq) -> PathBuf {
    req.socket_root
        .join(&req.own_slug)
        .join(format!("{}.socket", req.peer_slug))
}

/// Send one `SubmitAnswer` to the source peer and return its outcome.
///
/// # Errors
/// - [`CrossbridgeError::PeerUnreachable`] if the peer's socket cannot be
///   connected (the source peer is offline) **or** a socket read/write exceeds
///   [`ANSWER_IO_TIMEOUT`] (a stalled peer is operationally unreachable) — the
///   retryable `answer_unreachable` condition.
/// - [`CrossbridgeError::Wire`] if the frame cannot be written or the response
///   read for any non-timeout reason.
/// - [`CrossbridgeError::PeerRejected`] if the peer server answers with an
///   error.
pub fn answer(req: AnswerReq) -> Result<AnswerOutcome> {
    let socket_path = answer_socket_path(&req);
    let request = ClientRequest::Answer(SubmitAnswer {
        source_uuid: req.source_uuid.clone(),
        comments: req
            .comments
            .iter()
            .map(|c| WireComment {
                content: c.content.clone(),
                kind: c.kind.clone(),
            })
            .collect(),
        attachments: Vec::new(),
    });
    round_trip(&socket_path, &req.peer_slug, &request)
}

/// Connect, write the request frame, read the response frame, map to plain.
fn round_trip(
    socket_path: &Path,
    peer_slug: &str,
    request: &ClientRequest,
) -> Result<AnswerOutcome> {
    round_trip_with_timeout(socket_path, peer_slug, request, ANSWER_IO_TIMEOUT)
}

/// [`round_trip`] with an explicit socket deadline (parameterized for tests).
fn round_trip_with_timeout(
    socket_path: &Path,
    peer_slug: &str,
    request: &ClientRequest,
    io_timeout: Duration,
) -> Result<AnswerOutcome> {
    let mut stream =
        UnixStream::connect(socket_path).map_err(|source| CrossbridgeError::PeerUnreachable {
            peer: peer_slug.to_owned(),
            socket: socket_path.to_path_buf(),
            source: Box::new(source),
        })?;
    // Bound every subsequent blocking op: an untrusted peer that accepts and
    // then goes silent (or dribbles bytes under a large announced frame) must
    // not stall the orchestrator's poll thread. The upstream handler has no
    // read timeout of its own; this is the embedder's defense.
    stream
        .set_read_timeout(Some(io_timeout))
        .map_err(|source| CrossbridgeError::Wire {
            peer: peer_slug.to_owned(),
            source: Box::new(source),
        })?;
    stream
        .set_write_timeout(Some(io_timeout))
        .map_err(|source| CrossbridgeError::Wire {
            peer: peer_slug.to_owned(),
            source: Box::new(source),
        })?;
    write_message_sync(&mut stream, request)
        .map_err(|source| classify_wire_error(source, peer_slug, socket_path))?;
    let response: ServerResponse = read_message_sync(&mut stream)
        .map_err(|source| classify_wire_error(source, peer_slug, socket_path))?;
    match response {
        ServerResponse::Ok { issue_id } => Ok(AnswerOutcome {
            remote_issue_id: issue_id,
        }),
        ServerResponse::Error { message } => Err(CrossbridgeError::PeerRejected {
            peer: peer_slug.to_owned(),
            message,
        }),
    }
}

/// `true` if a framing error is an elapsed socket read/write deadline. The
/// `UnixStream`'s `set_{read,write}_timeout` surfaces as a `WouldBlock`
/// (`EWOULDBLOCK`/`EAGAIN`) or `TimedOut` io error, which framing wraps in
/// [`ProtocolError::Io`].
fn is_io_timeout(err: &ProtocolError) -> bool {
    matches!(
        err,
        ProtocolError::Io(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
    )
}

/// Map a framing error from the round-trip to an adapter error. A socket
/// timeout on a silent/slow untrusted peer is operationally the same as an
/// unreachable peer, so it maps to the **retryable**
/// [`CrossbridgeError::PeerUnreachable`]; any other framing failure is a
/// [`CrossbridgeError::Wire`].
fn classify_wire_error(
    source: ProtocolError,
    peer_slug: &str,
    socket_path: &Path,
) -> CrossbridgeError {
    if is_io_timeout(&source) {
        CrossbridgeError::PeerUnreachable {
            peer: peer_slug.to_owned(),
            socket: socket_path.to_path_buf(),
            source: Box::new(source),
        }
    } else {
        CrossbridgeError::Wire {
            peer: peer_slug.to_owned(),
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_req(root: &Path) -> AnswerReq {
        AnswerReq {
            peer_slug: "firmware".to_owned(),
            own_slug: "tools".to_owned(),
            socket_root: root.to_path_buf(),
            source_uuid: "abc-123".to_owned(),
            comments: vec![AnswerComment {
                kind: "result".to_owned(),
                content: "done".to_owned(),
            }],
        }
    }

    #[test]
    fn socket_path_matches_crossbridge_layout() {
        let req = sample_req(Path::new("/run/xb"));
        assert_eq!(
            answer_socket_path(&req),
            PathBuf::from("/run/xb/tools/firmware.socket")
        );
    }

    #[test]
    fn missing_peer_socket_is_unreachable_not_wire() {
        // No socket bound: connect fails, and we must classify it as the
        // retryable PeerUnreachable, never Wire or PeerRejected. This is the
        // load-bearing distinction the answer state machine keys off.
        let tmp = tempfile::tempdir().expect("tempdir");
        let req = sample_req(tmp.path());
        let err = answer(req).expect_err("connect must fail with no socket bound");
        match err {
            CrossbridgeError::PeerUnreachable { peer, socket, .. } => {
                assert_eq!(peer, "firmware");
                assert_eq!(socket, tmp.path().join("tools").join("firmware.socket"));
            }
            other => panic!("expected PeerUnreachable, got {other:?}"),
        }
    }

    #[test]
    fn timeout_io_error_classifies_as_retryable_unreachable() {
        // A socket read/write deadline surfaces as WouldBlock/TimedOut; it must
        // land on the retryable PeerUnreachable, never Wire — the answer state
        // machine keys its retry off exactly this distinction.
        for kind in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut] {
            let source = ProtocolError::Io(std::io::Error::from(kind));
            let err = classify_wire_error(
                source,
                "firmware",
                Path::new("/run/xb/tools/firmware.socket"),
            );
            assert!(
                matches!(err, CrossbridgeError::PeerUnreachable { .. }),
                "{kind:?} must map to PeerUnreachable, got {err:?}"
            );
        }
    }

    #[test]
    fn non_timeout_io_error_classifies_as_wire() {
        // Any other framing failure (a genuine broken connection, a decode
        // error) stays Wire — the terminal, non-retryable condition.
        let source = ProtocolError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        let err = classify_wire_error(
            source,
            "firmware",
            Path::new("/run/xb/tools/firmware.socket"),
        );
        assert!(
            matches!(err, CrossbridgeError::Wire { .. }),
            "a non-timeout io error must map to Wire, got {err:?}"
        );
    }

    /// End-to-end read-timeout defense: a peer that accepts the connection and
    /// then goes silent (never replies) must not stall the caller. The bounded
    /// read deadline fires and maps to the retryable `PeerUnreachable`. Uses a
    /// short deadline via `round_trip_with_timeout` so the test is fast; needs
    /// no supervisor, only a raw stalling listener.
    #[test]
    fn stalled_peer_read_times_out_as_unreachable() {
        use std::os::unix::net::UnixListener;
        use std::time::Instant;

        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("tools");
        std::fs::create_dir_all(&dir).expect("create own-slug dir");
        let socket = dir.join("firmware.socket");
        let listener = UnixListener::bind(&socket).expect("bind listener");

        // Accept once, then hold the connection open and silent past the test's
        // deadline — never sending a response frame.
        let stall = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(30));
                drop(stream);
            }
        });

        let request = ClientRequest::Answer(SubmitAnswer {
            source_uuid: "abc-123".to_owned(),
            comments: vec![WireComment {
                content: "done".to_owned(),
                kind: "result".to_owned(),
            }],
            attachments: Vec::new(),
        });

        let deadline = Duration::from_millis(200);
        let start = Instant::now();
        let err = round_trip_with_timeout(&socket, "firmware", &request, deadline)
            .expect_err("a stalled peer read must fail, not hang");
        let elapsed = start.elapsed();

        assert!(
            matches!(err, CrossbridgeError::PeerUnreachable { .. }),
            "a stalled read must map to PeerUnreachable, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the read deadline must bound the wait (took {elapsed:?})"
        );
        // The stall thread outlives the test's read; the test process exits.
        drop(stall);
    }
}
