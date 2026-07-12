//! The static QA gate (REQ-9, REQ-9a, AC-7).
//!
//! After every Implementer commit the orchestrator runs the project's
//! `.orchestrator/static_qa.sh` against the worker's workspace and derives a
//! pass/fail verdict **from the script's process exit code alone**. The agent
//! never decides pass/fail; the orchestrator owns the verdict deterministically
//! (REQ-9). This module produces only the structured verdict — turning a
//! [`QaOutcome::Fail`] into a `--kind blocker` comment and re-spawning the
//! Implementer is the pump's job (S3), not this module's.
//!
//! # Verdict vs. poison — the load-bearing distinction
//!
//! There are two failure axes, and conflating them is a correctness bug:
//!
//! - **A QA tool said no.** The script ran to completion and exited non-zero
//!   with a real tool's exit code (clippy found a lint → 101, a test failed, a
//!   hook rejected). That is the *routine* path: [`QaGate::run`] returns
//!   `Ok(`[`QaOutcome::Fail`]`)` carrying the concrete non-zero exit code and
//!   the last ~[`TAIL_LINES`] lines of combined output. The pump posts it as a
//!   blocker and re-spawns (REQ-9, AC-7).
//! - **The gate itself is broken, hung, or died.** The script is missing or
//!   un-spawnable; `bash` couldn't exec it (126) or a command inside it was not
//!   found (127); it was killed by a signal (OOM); or it wedged past the
//!   timeout. None of those is a failed *check* — they are repo/host
//!   misconfiguration or an environment anomaly the Implementer cannot fix.
//!   [`QaGate::run`] returns `Err(`[`QaError`]`)`, which the orchestrator maps
//!   to the poison state `phase:orchestrator-error` for human inspection, never
//!   a blocker (see the design's error-handling section: "`static_qa.sh` itself
//!   errors" is distinct from "a QA tool returned non-zero").
//!
//! The type signature encodes the distinction: `Result<QaOutcome, QaError>`.
//! The `Ok` arm is the deterministic verdict (`Pass`/`Fail`); the `Err` arm is
//! poison. A caller that matches on the `Result` cannot accidentally route a
//! real QA failure to the poison state or vice versa.
//!
//! ## Exit-code classification
//!
//! | script exit           | outcome                                    |
//! |-----------------------|--------------------------------------------|
//! | `0`                   | `Ok(Pass)`                                 |
//! | `126` / `127`         | `Err(ScriptItselfErrored)` — poison        |
//! | any other non-zero    | `Ok(Fail { exit_code, .. })` — blocker     |
//! | killed by signal      | `Err(Killed)` — poison                     |
//! | exceeded the timeout  | `Err(TimedOut)` — poison                   |
//!
//! `126` is bash's "found but cannot execute" and `127` is "command not found"
//! *inside* the script (e.g. `cargo` off PATH) — both mean the gate never ran
//! the tools, so they are broken-gate poison, not a worker-code blocker. A real
//! tool failure like `cargo test` exiting `101` stays a `Fail`.
//!
//! # The verdict never parses output for "PASS"
//!
//! [`QaOutcome`] is computed purely from the child's exit status. The script's
//! stdout/stderr is captured *only* to fill a [`Fail`]'s [`OutputTail`] for the
//! blocker body (and a poison variant's inspection message) — it is never
//! scanned for a magic pass/fail string (REQ-9: the orchestrator does not trust
//! self-assessments).
//!
//! [`Fail`]: QaOutcome::Fail
//!
//! # No forbidden shell-out (AC-24)
//!
//! Running `.orchestrator/static_qa.sh` is the *sanctioned* AC-24 exception
//! (REQ-1a exception (b)): a user-supplied script is a shell contract, so it is
//! run via `bash <path>`. This is the one place the orchestrator executes a
//! user script; it is **not** a forbidden shell-out. No `jj`/`git`/`gh`/
//! `crosslink`/`zellij` subprocess is constructed here — the no-shell-out lint
//! bans exactly those names, and `bash` is not among them.
//!
//! # Known limitation: grandchild processes survive a kill
//!
//! On timeout the gate calls [`std::process::Child::kill`], which sends
//! `SIGKILL` to the direct `bash` child only. Any grandchildren the script
//! spawned (a `cargo` subprocess, its `rustc` invocations) are *not* reaped —
//! killing a whole process group needs a `setpgid` via `pre_exec`, which is
//! `unsafe` and this crate is `#![forbid(unsafe_code)]`. For the MVP this is
//! acceptable: the orchestrator surfaces the hang as poison and stops
//! advancing the issue regardless. Follow-up: adopt a small no-unsafe
//! process-group helper (or the `wait-timeout` + `nix`/`command-group` crates)
//! to reap the tree.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use vetinari_error::QaError;

/// The script the gate runs, relative to the workspace root (REQ-9). Committed
/// and whitelisted in the project's `.gitignore` (see the fixture). Kept as a
/// constant so the layout in `.design/vdd-orchestrator.md` and the code agree.
pub const STATIC_QA_SCRIPT: &str = ".orchestrator/static_qa.sh";

/// How many trailing lines of combined QA output a [`QaOutcome::Fail`] retains
/// for the blocker body (REQ-9 / AC-7: "last ~50 lines"). A named budget rather
/// than a magic literal so the design's "~50 lines" and the code stay in sync,
/// and so the cap is testable.
pub const TAIL_LINES: usize = 50;

/// Default wall-clock budget for one QA run before the gate kills the child and
/// returns [`QaError::TimedOut`]. A wedged `static_qa.sh` must not block the
/// headless pump forever — no heartbeat watchdog covers the orchestrator-run
/// gate — so the gate self-bounds. Ten minutes comfortably fits a cold
/// `cargo test` build while still catching a true hang.
pub const DEFAULT_QA_TIMEOUT: Duration = Duration::from_secs(600);

/// Upper bound on bytes of combined output the gate keeps in memory. A runaway
/// script (an infinite `echo` loop) must not OOM the orchestrator, and
/// [`OutputTail`] only needs the *tail* anyway, so the reader retains at most
/// this many trailing bytes and discards the rest. 512 KiB is far more than the
/// last ~50 lines ever need but small enough to be harmless.
pub const MAX_CAPTURE_BYTES: usize = 512 * 1024;

/// How long to sleep between `try_wait` polls of the child. Short enough that
/// the timeout deadline is honored to within this granularity; long enough that
/// the poll loop doesn't spin the CPU.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

// ============================================================================
// OutputTail
// ============================================================================

/// The last ~[`TAIL_LINES`] lines of a failed QA run's combined stdout+stderr,
/// preserved verbatim for the blocker comment body.
///
/// A newtype over the captured string rather than a bare `String`: it can only
/// be built by [`OutputTail::from_output`], which owns the tail-capping policy,
/// so no caller can hand a full, uncapped transcript to a [`QaOutcome::Fail`].
/// It carries no pass/fail meaning — the verdict lives in [`QaOutcome`], derived
/// from the exit code — it is purely the diagnostic text the Implementer
/// re-spawn receives as input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputTail(String);

impl OutputTail {
    /// Build a tail from raw combined output, keeping only the last
    /// [`TAIL_LINES`] lines.
    ///
    /// Line boundaries are `\n`, `\r`, **and** `\r\n` — not just `\n`. Cargo and
    /// pytest render progress with bare `\r` carriage returns (a spinner
    /// overwriting one line); splitting on `\n` alone would collapse a whole
    /// progress stream into a single giant "line" and make the last-N cap a
    /// no-op. Treating `\r` as a boundary keeps the cap meaningful for spinner
    /// output. Like `str::lines()`, a single trailing terminator does not add a
    /// blank final line. Fewer than `TAIL_LINES` lines are returned whole.
    fn from_output(raw: &str) -> Self {
        let lines = split_lines(raw);
        let start = lines.len().saturating_sub(TAIL_LINES);
        OutputTail(lines[start..].join("\n"))
    }

    /// The retained tail text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The number of lines retained (at most [`TAIL_LINES`]).
    pub fn line_count(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            // `self.0` was rejoined with `\n`, so counting `\n`-lines is exact.
            self.0.split('\n').count()
        }
    }
}

impl std::fmt::Display for OutputTail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Split `raw` into lines on `\n`, `\r`, or `\r\n`, dropping the terminators.
///
/// `str::lines()` splits only on `\n` (and strips a trailing `\r`), so a stream
/// of `\r`-separated progress spinners becomes one line. This splitter treats a
/// carriage return as its own boundary and folds `\r\n` into a single break so a
/// DOS-style transcript isn't doubled with blank lines.
fn split_lines(raw: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let bytes = raw.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                lines.push(&raw[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                lines.push(&raw[start..i]);
                // Fold `\r\n` into one boundary.
                if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                    i += 2;
                } else {
                    i += 1;
                }
                start = i;
            }
            _ => i += 1,
        }
    }
    // Mirror `str::lines()`: a terminator at the very end does not yield a
    // trailing empty line. Only push a final segment if there is unterminated
    // text after the last boundary.
    if start < bytes.len() {
        lines.push(&raw[start..]);
    }
    lines
}

// ============================================================================
// QaOutcome — the deterministic verdict
// ============================================================================

/// The QA gate's verdict for one Implementer commit — a *closed* enum computed
/// solely from the QA script's process exit code (REQ-9).
///
/// This is only the `Ok` half of [`QaGate::run`]'s result: a broken, killed, or
/// hung gate is a [`QaError`], not an `Outcome`, so the two failure axes never
/// collapse into one value. Because every non-verdict exit (126/127, signal
/// death, timeout) is poison, a `Fail` here always carries a concrete non-zero
/// `exit_code: i32` — the pump can build the blocker comment directly from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QaOutcome {
    /// The script exited 0 — QA passed. The issue advances (REQ-9:
    /// `phase:adversary-review`, or `phase:converged` in MVP).
    Pass,
    /// The script exited with a concrete non-zero code that is *not* a
    /// broken-gate code (126/127) — a QA tool said no. Carries that exit code
    /// and the tail of the combined output, which the pump turns into a
    /// `--kind blocker` and feeds to the re-spawned Implementer (REQ-9, AC-7).
    /// This is a routine failed check, **not** poison.
    Fail {
        /// The QA tool's concrete non-zero exit code (e.g. `101` from
        /// `cargo test`). Never `0`, never `126`/`127`, never signal death —
        /// those are poison, handled as [`QaError`] before a `Fail` is built.
        exit_code: i32,
        /// The last ~[`TAIL_LINES`] lines of combined stdout+stderr.
        output_tail: OutputTail,
    },
}

impl QaOutcome {
    /// Whether QA passed.
    pub fn is_pass(&self) -> bool {
        matches!(self, QaOutcome::Pass)
    }
}

// ============================================================================
// QaGate
// ============================================================================

/// Runs the project's static QA script against a worker's workspace and returns
/// the orchestrator-owned verdict (REQ-9).
///
/// Holds the workspace root and a timeout; [`run`](QaGate::run) resolves the
/// script relative to the root and executes it with that root as the working
/// directory, so the QA tools see exactly the tree the Implementer just
/// committed, and kills the child if it exceeds the timeout.
#[derive(Debug, Clone)]
pub struct QaGate {
    /// The worker's workspace root — both the script's parent-of-parent and its
    /// working directory.
    workspace: PathBuf,
    /// Wall-clock budget before the gate kills the child (poison, not a Fail).
    timeout: Duration,
}

impl QaGate {
    /// A gate over the worker's workspace root `workspace`, using
    /// [`DEFAULT_QA_TIMEOUT`]. The script is expected at
    /// `<workspace>/.orchestrator/static_qa.sh`.
    pub fn new(workspace: impl Into<PathBuf>) -> Self {
        QaGate {
            workspace: workspace.into(),
            timeout: DEFAULT_QA_TIMEOUT,
        }
    }

    /// Override the run timeout (builder-style). A wedged script past this
    /// budget is killed and surfaced as [`QaError::TimedOut`] poison. Used by
    /// tests to force a fast timeout; production uses [`DEFAULT_QA_TIMEOUT`].
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The absolute path of the static QA script this gate would run.
    pub fn script_path(&self) -> PathBuf {
        self.workspace.join(STATIC_QA_SCRIPT)
    }

    /// Run the static QA gate.
    ///
    /// Executes `bash <workspace>/.orchestrator/static_qa.sh` with `<workspace>`
    /// as the working directory, draining combined stdout+stderr into a
    /// byte-bounded buffer (at most [`MAX_CAPTURE_BYTES`], tail kept), and
    /// derives the verdict from the exit status per the classification table in
    /// the module docs:
    ///
    /// - exit 0 → `Ok(`[`QaOutcome::Pass`]`)`,
    /// - exit 126/127 → [`QaError::ScriptItselfErrored`] (broken gate, poison),
    /// - any other non-zero → `Ok(`[`QaOutcome::Fail`]`)` with the code and tail,
    /// - killed by a signal → [`QaError::Killed`] (poison),
    /// - exceeded the timeout → [`QaError::TimedOut`] (poison).
    ///
    /// A broken gate is an `Err`, never a `Fail`:
    ///
    /// - the script does not exist → [`QaError::ScriptNotFound`],
    /// - `bash` is missing or the path is unreachable so the child cannot even
    ///   be spawned → [`QaError::ScriptUnspawnable`].
    ///
    /// All `Err` variants are poison → `phase:orchestrator-error` (the design's
    /// error-handling section), never a blocker.
    pub fn run(&self) -> Result<QaOutcome, QaError> {
        let script = self.script_path();

        // A missing script is poison, not a failed check — surface it as its own
        // typed error *before* spawning so it is distinguishable from a `bash`
        // exec failure and never masquerades as a QA tool saying no.
        if !script.exists() {
            return Err(QaError::ScriptNotFound { path: script });
        }

        // The AC-24-sanctioned shell-out: a user-supplied script is a shell
        // contract (REQ-1a exception (b)). stdout and stderr are piped and
        // drained concurrently (below) so a runaway script can't deadlock on a
        // full pipe buffer. Run with the workspace as cwd so QA tools see the
        // tree the Implementer committed.
        let mut child = Command::new("bash")
            .arg(&script)
            .current_dir(&self.workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| QaError::ScriptUnspawnable {
                path: script,
                source,
            })?;

        // Drain both streams on their own threads into byte-bounded buffers.
        // Concurrent draining is required: if we polled `try_wait` without
        // reading, a script producing more than one pipe buffer of output would
        // block on write forever and never exit — a deadlock. Bounding each
        // buffer keeps the tail while capping memory (MAX_CAPTURE_BYTES).
        let stdout_reader = child
            .stdout
            .take()
            .map(|s| thread::spawn(move || drain_bounded(s)));
        let stderr_reader = child
            .stderr
            .take()
            .map(|s| thread::spawn(move || drain_bounded(s)));

        // Poll for exit until the deadline. On timeout, kill + reap the child so
        // it doesn't linger, then return poison.
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        // Kill the direct child and reap it. Grandchildren may
                        // survive (see the module-level known-limitation note);
                        // acceptable for MVP since we surface the hang as poison.
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(QaError::TimedOut {
                            after: self.timeout,
                        });
                    }
                    thread::sleep(POLL_INTERVAL);
                }
                Err(source) => {
                    // `try_wait` failing is an OS-level anomaly around the child
                    // handle — treat as an unspawnable/broken gate (poison).
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(QaError::ScriptUnspawnable {
                        path: self.script_path(),
                        source,
                    });
                }
            }
        };

        // Join the drain threads (the child has exited, so the pipes are closed
        // and the readers return). A panicked reader thread degrades to empty
        // output rather than poisoning the run — the verdict comes from the exit
        // code, and losing a tail is never worth aborting the gate.
        let stdout = stdout_reader
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        let stderr = stderr_reader
            .and_then(|h| h.join().ok())
            .unwrap_or_default();

        classify(&status, stdout, stderr)
    }
}

/// Turn a finished child's [`std::process::ExitStatus`] plus its captured output
/// into the verdict-or-poison per the module's classification table.
fn classify(
    status: &std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> Result<QaOutcome, QaError> {
    if status.success() {
        return Ok(QaOutcome::Pass);
    }

    let combined = combine(&stdout, &stderr);

    match status.code() {
        // 126: found but not executable / cannot exec. 127: a command inside the
        // script was not found (e.g. `cargo` off PATH). Both mean the gate never
        // ran the tools — broken gate, poison, not a worker-code blocker.
        Some(code @ (126 | 127)) => Err(QaError::ScriptItselfErrored {
            exit_code: code,
            message: OutputTail::from_output(&combined).0,
        }),
        // A real QA tool said no (e.g. `cargo test` → 101). The routine blocker.
        Some(code) => Ok(QaOutcome::Fail {
            exit_code: code,
            output_tail: OutputTail::from_output(&combined),
        }),
        // No exit code → terminated by a signal (OOM kill, SIGKILL). An
        // environment anomaly, not a failed check — poison.
        None => Err(QaError::Killed {
            signal: signal_of(status),
            message: OutputTail::from_output(&combined).0,
        }),
    }
}

/// The terminating signal for a signal-killed child, when the platform exposes
/// it. `ExitStatusExt::signal` is a *safe* std API on unix (no `unsafe`, no
/// libc), so reading it does not violate the crate's `forbid(unsafe_code)`.
#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn signal_of(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Concatenate stdout then stderr for the tail, decoding lossily. Each stream's
/// internal order is preserved — which is what a failing tool's diagnostics read
/// like — and the exact exit code is the deterministic verdict either way.
fn combine(stdout: &[u8], stderr: &[u8]) -> String {
    let mut combined = String::from_utf8_lossy(stdout).into_owned();
    let stderr = String::from_utf8_lossy(stderr);
    if !stderr.is_empty() {
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&stderr);
    }
    combined
}

/// Read `src` to EOF, retaining at most [`MAX_CAPTURE_BYTES`] **trailing** bytes.
///
/// A runaway script must not OOM the orchestrator, and [`OutputTail`] only needs
/// the end of the transcript. Reads in chunks; once the buffer would exceed the
/// cap, drops leading bytes so it never grows past `MAX_CAPTURE_BYTES`. A read
/// error stops draining and returns what was captured so far — the verdict comes
/// from the exit code regardless.
fn drain_bounded(mut src: impl Read) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    loop {
        match src.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_CAPTURE_BYTES {
                    let drop = buf.len() - MAX_CAPTURE_BYTES;
                    buf.drain(..drop);
                }
            }
            Err(_) => break,
        }
    }
    buf
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::Path;

    use tempfile::TempDir;

    /// Materialize a workspace with a `.orchestrator/static_qa.sh` whose body is
    /// `body`, marked executable. Returns the tempdir (hold it) and its root.
    fn workspace_with_script(body: &str) -> (TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let dir = root.join(".orchestrator");
        fs::create_dir_all(&dir).expect("mkdir .orchestrator");
        let script = dir.join("static_qa.sh");
        fs::write(&script, body).expect("write static_qa.sh");
        set_executable(&script);
        (tmp, root)
    }

    #[cfg(unix)]
    fn set_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod +x");
    }

    #[cfg(not(unix))]
    fn set_executable(_path: &Path) {}

    // --- Verdict: pass ------------------------------------------------------

    /// AC-7 pass (unit): an exit-0 script yields `Pass`. Uses a trivial script
    /// so the test is hermetic and fast; the fixture-backed variant that runs a
    /// real `cargo test` lives in `tests/qa_gate.rs`.
    #[test]
    fn exit_zero_is_pass() {
        let (_tmp, root) = workspace_with_script("#!/usr/bin/env bash\nexit 0\n");
        let outcome = QaGate::new(&root).run().expect("gate runs");
        assert_eq!(outcome, QaOutcome::Pass);
        assert!(outcome.is_pass());
    }

    // --- Verdict: fail ------------------------------------------------------

    /// AC-7 fail (unit): a non-zero script yields `Fail` carrying the exit code
    /// and a tail containing the failing output — never a poison `Err`.
    #[test]
    fn nonzero_exit_is_fail_with_tail() {
        let (_tmp, root) = workspace_with_script(
            "#!/usr/bin/env bash\necho 'error: something broke' >&2\nexit 17\n",
        );
        let outcome = QaGate::new(&root)
            .run()
            .expect("gate runs (fail is Ok, not Err)");
        match outcome {
            QaOutcome::Fail {
                exit_code,
                output_tail,
            } => {
                assert_eq!(exit_code, 17);
                assert!(
                    output_tail.as_str().contains("error: something broke"),
                    "tail must carry the failing output, got {:?}",
                    output_tail.as_str()
                );
            }
            QaOutcome::Pass => panic!("expected Fail, got Pass"),
        }
    }

    /// The verdict comes from the exit code, never from the script printing a
    /// "PASS"/"FAIL" string: a script that prints `PASS` on stdout but exits
    /// non-zero is a `Fail`, and one that prints `FAIL` but exits 0 is a `Pass`.
    #[test]
    fn verdict_is_exit_code_not_stdout_string() {
        let (_t1, r1) = workspace_with_script("#!/usr/bin/env bash\necho PASS\nexit 1\n");
        assert!(matches!(
            QaGate::new(&r1).run().expect("runs"),
            QaOutcome::Fail { .. }
        ));

        let (_t2, r2) = workspace_with_script("#!/usr/bin/env bash\necho FAIL\nexit 0\n");
        assert_eq!(QaGate::new(&r2).run().expect("runs"), QaOutcome::Pass);
    }

    /// A real QA-tool exit code like `101` (cargo test) stays a `Fail`, not
    /// poison — only 126/127 are the broken-gate codes.
    #[test]
    fn tool_exit_101_is_fail_not_poison() {
        let (_tmp, root) = workspace_with_script("#!/usr/bin/env bash\nexit 101\n");
        let outcome = QaGate::new(&root).run().expect("101 is a routine Fail");
        assert!(matches!(outcome, QaOutcome::Fail { exit_code: 101, .. }));
    }

    // --- Poison: broken-gate exit codes 126 / 127 ---------------------------

    /// Exit 127 (command-not-found inside the script, e.g. `cargo` missing) is a
    /// broken gate → `ScriptItselfErrored` poison, never a blocker `Fail`.
    #[test]
    fn exit_127_command_not_found_is_poison() {
        let (_tmp, root) =
            workspace_with_script("#!/usr/bin/env bash\ndefinitely-not-a-real-command-xyzzy\n");
        let err = QaGate::new(&root).run().unwrap_err();
        match err {
            QaError::ScriptItselfErrored { exit_code, .. } => assert_eq!(exit_code, 127),
            other => panic!("expected ScriptItselfErrored(127), got {other:?}"),
        }
    }

    /// Exit 126 (found but not executable — here, trying to exec a directory) is
    /// a broken gate → `ScriptItselfErrored` poison.
    #[test]
    fn exit_126_not_executable_is_poison() {
        // Run a directory as a program: bash reports 126 (cannot execute).
        let (_tmp, root) = workspace_with_script("#!/usr/bin/env bash\nmkdir -p adir\n./adir\n");
        let err = QaGate::new(&root).run().unwrap_err();
        match err {
            QaError::ScriptItselfErrored { exit_code, .. } => assert_eq!(exit_code, 126),
            other => panic!("expected ScriptItselfErrored(126), got {other:?}"),
        }
    }

    // --- Poison: signal death -----------------------------------------------

    /// A signal-killed gate (here the script kills itself with SIGKILL) yields
    /// no exit code → `Killed` poison, never `Fail`. OOM presents the same way.
    #[cfg(unix)]
    #[test]
    fn signal_death_is_poison_not_fail() {
        let (_tmp, root) = workspace_with_script("#!/usr/bin/env bash\nkill -9 $$\n");
        let err = QaGate::new(&root).run().unwrap_err();
        match err {
            QaError::Killed { signal, .. } => {
                // SIGKILL is 9 where the platform exposes the signal.
                assert_eq!(signal, Some(9), "expected SIGKILL, got {signal:?}");
            }
            other => panic!("expected Killed poison, got {other:?}"),
        }
    }

    // --- Poison: timeout ----------------------------------------------------

    /// A script that sleeps past a short timeout is killed and surfaced as
    /// `TimedOut` poison — the gate never blocks the pump forever.
    #[test]
    fn slow_script_times_out_as_poison() {
        let (_tmp, root) = workspace_with_script("#!/usr/bin/env bash\nsleep 30\n");
        let start = Instant::now();
        let err = QaGate::new(&root)
            .with_timeout(Duration::from_secs(1))
            .run()
            .unwrap_err();
        assert!(
            matches!(err, QaError::TimedOut { .. }),
            "a wedged script must be TimedOut poison, got {err:?}"
        );
        // The gate returned near the timeout, not after the full 30s sleep.
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "gate must return promptly after the timeout, took {:?}",
            start.elapsed()
        );
    }

    // --- Tail capping -------------------------------------------------------

    /// A script emitting more than `TAIL_LINES` lines has its tail capped to
    /// exactly the last `TAIL_LINES`, and those are the *last* ones (not the
    /// first).
    #[test]
    fn tail_is_capped_to_the_budget() {
        // Print 200 numbered lines then fail.
        let body =
            "#!/usr/bin/env bash\nfor i in $(seq 1 200); do echo \"line-$i\"; done\nexit 3\n";
        let (_tmp, root) = workspace_with_script(body);
        let outcome = QaGate::new(&root).run().expect("runs");
        let QaOutcome::Fail { output_tail, .. } = outcome else {
            panic!("expected Fail");
        };
        assert_eq!(
            output_tail.line_count(),
            TAIL_LINES,
            "tail must be capped to exactly TAIL_LINES lines"
        );
        // The kept lines are the LAST ones: line-200 present, line-151 present,
        // line-149 dropped.
        assert!(output_tail.as_str().contains("line-200"));
        assert!(output_tail.as_str().contains("line-151"));
        assert!(
            !output_tail.as_str().contains("line-149"),
            "lines before the last TAIL_LINES must be dropped"
        );
    }

    /// `\r`-separated progress spinners (as cargo/pytest emit) are split into
    /// real lines, so the last-N cap is meaningful — not collapsed into one
    /// giant line that defeats the budget.
    #[test]
    fn carriage_return_progress_lines_are_split_for_the_tail() {
        // Emit 200 progress updates separated by bare `\r` (a spinner
        // overwriting one terminal line), then a newline and a failure.
        let body = "#!/usr/bin/env bash\n\
            for i in $(seq 1 200); do printf 'progress-%d\\r' \"$i\"; done\n\
            printf '\\ndone\\n'\nexit 5\n";
        let (_tmp, root) = workspace_with_script(body);
        let QaOutcome::Fail { output_tail, .. } = QaGate::new(&root).run().expect("runs") else {
            panic!("expected Fail");
        };
        // Without \r-splitting the whole spinner stream is one line and the cap
        // is a no-op; with it, we keep exactly the last TAIL_LINES real lines.
        assert_eq!(
            output_tail.line_count(),
            TAIL_LINES,
            "the \\r spinner stream must split into lines so the cap applies"
        );
        assert!(
            output_tail.as_str().contains("progress-200") || output_tail.as_str().contains("done"),
            "tail keeps the last real lines, got:\n{}",
            output_tail.as_str()
        );
        assert!(
            !output_tail.as_str().contains("progress-1\r"),
            "early spinner frames must be dropped by the cap"
        );
    }

    /// Fewer than `TAIL_LINES` lines are returned whole, uncapped.
    #[test]
    fn short_output_is_returned_whole() {
        let (_tmp, root) =
            workspace_with_script("#!/usr/bin/env bash\necho one\necho two\nexit 1\n");
        let QaOutcome::Fail { output_tail, .. } = QaGate::new(&root).run().expect("runs") else {
            panic!("expected Fail");
        };
        assert_eq!(output_tail.line_count(), 2);
        assert!(output_tail.as_str().contains("one"));
        assert!(output_tail.as_str().contains("two"));
    }

    // --- Poison: distinct from Fail -----------------------------------------

    /// A workspace with NO `.orchestrator/static_qa.sh` is poison — a distinct
    /// typed `Err`, never a `Fail`. This is the load-bearing distinction: a
    /// broken gate routes to `phase:orchestrator-error`, not a blocker.
    #[test]
    fn missing_script_is_poison_not_fail() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        // No .orchestrator/ dir at all.
        let err = QaGate::new(&root).run().unwrap_err();
        assert!(
            matches!(err, QaError::ScriptNotFound { .. }),
            "a missing script must be ScriptNotFound poison, got {err:?}"
        );
    }

    /// A broken gate whose script cannot even be reached is poison — an `Err`,
    /// never a `Fail`. Making the `.orchestrator/` directory non-searchable
    /// denies `stat`, so `script.exists()` is false and the gate returns
    /// `ScriptNotFound` (or, if a host stats differently, `ScriptUnspawnable`).
    /// The invariant under test is "a broken gate is poison, never a `Fail`",
    /// which both poison variants satisfy — the point is that it is *not* the
    /// `Ok(Fail)` verdict a real failing check produces.
    ///
    /// Root skips DAC permission checks, so a non-searchable directory is still
    /// traversable and the test is meaningless there. We detect that case
    /// dynamically — if the perms were bypassed, `script.exists()` stays true
    /// and the gate produces a verdict rather than poison — and skip the
    /// assertion instead of yielding a misleading failure.
    #[cfg(unix)]
    #[test]
    fn unreachable_script_is_poison_not_fail() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let dir = root.join(".orchestrator");
        fs::create_dir_all(&dir).expect("mkdir");
        let script = dir.join("static_qa.sh");
        fs::write(&script, "#!/usr/bin/env bash\nexit 0\n").expect("write");
        // Non-searchable dir: reaching the script inside is denied for non-root.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).expect("dir perms");

        // If DAC is bypassed (running as root), the script is still reachable —
        // the poison scenario cannot be constructed, so skip.
        let perms_enforced = !script.exists();

        let result = QaGate::new(&root).run();

        // Restore perms so the tempdir can be cleaned up on drop.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("restore");

        if perms_enforced {
            assert!(
                matches!(
                    result,
                    Err(QaError::ScriptNotFound { .. }) | Err(QaError::ScriptUnspawnable { .. })
                ),
                "a broken gate must be poison (Err), never a Fail, got {result:?}"
            );
        }
    }

    // --- OutputTail / line splitting unit -----------------------------------

    #[test]
    fn output_tail_keeps_last_n() {
        let raw: String = (1..=100).map(|i| format!("l{i}\n")).collect();
        let tail = OutputTail::from_output(&raw);
        assert_eq!(tail.line_count(), TAIL_LINES);
        assert!(tail.as_str().contains("l100"));
        assert!(tail.as_str().contains("l51"));
        assert!(!tail.as_str().contains("l50\n"));
    }

    #[test]
    fn output_tail_empty_is_zero_lines() {
        let tail = OutputTail::from_output("");
        assert_eq!(tail.line_count(), 0);
        assert_eq!(tail.as_str(), "");
    }

    /// `split_lines` treats `\n`, `\r`, and `\r\n` as boundaries and folds
    /// `\r\n` into one break (no doubled blank lines).
    #[test]
    fn split_lines_handles_all_terminators() {
        assert_eq!(split_lines("a\nb\rc\r\nd"), vec!["a", "b", "c", "d"]);
        // Like `str::lines()`, a single trailing terminator adds no blank line.
        assert_eq!(split_lines("a\n"), vec!["a"]);
        assert_eq!(split_lines("a\r"), vec!["a"]);
        assert_eq!(split_lines("a\r\n"), vec!["a"]);
        // An internal blank line IS preserved.
        assert_eq!(split_lines("a\n\nb"), vec!["a", "", "b"]);
        // Bare CR spinner frames split into distinct lines.
        assert_eq!(split_lines("x\ry\rz"), vec!["x", "y", "z"]);
    }

    /// The byte cap keeps the *tail*: a buffer over `MAX_CAPTURE_BYTES` retains
    /// exactly the last `MAX_CAPTURE_BYTES` bytes.
    #[test]
    fn drain_bounded_keeps_trailing_bytes() {
        let total = MAX_CAPTURE_BYTES + 50_000;
        let data = vec![b'x'; total - 3];
        let mut src = data.clone();
        src.extend_from_slice(b"END");
        let out = drain_bounded(std::io::Cursor::new(src));
        assert_eq!(out.len(), MAX_CAPTURE_BYTES, "capture is capped");
        assert_eq!(&out[out.len() - 3..], b"END", "the tail end is retained");
    }
}
