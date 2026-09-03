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
//! # The script runs INSIDE a hermetic bwrap sandbox (P0 threat-model fix)
//!
//! `static_qa.sh` is *worker-controlled*: it is a committed file in the worker's
//! read-write workspace, and its canonical body (`cargo test --locked --offline`)
//! compiles and runs worker-authored `build.rs`, proc-macros, and `#[test]`
//! code. Running it directly on the host would be arbitrary code execution on
//! the control plane, with the orchestrator's full environment (incl.
//! `GH_TOKEN`) and network — the single most dangerous gap in the threat model
//! (T1). So the gate runs the script **inside the same bwrap sandbox machinery
//! the worker spawn path uses** ([`SandboxHost::qa_mounts`]), wrapped in the
//! identical `env -i <allowlist>` scrub ([`crate::spawn::scrub_env_prefix`]):
//!
//! - **env scrubbed** — the child starts from `env -i PATH/HOME/TERM`, so
//!   `GH_TOKEN`, API keys, and the `bwrap` pin are never visible to the code
//!   under grading.
//! - **network denied** — `qa_mounts` adds `--unshare-net` (the worker path
//!   shares net for the Anthropic API; QA does not), so a malicious `build.rs`
//!   cannot exfiltrate. The canonical script is `--offline`, so this is
//!   legitimately hermetic.
//! - **host FS denied** — only `/nix` (RO), `/etc` (RO), the RO nix/git/jj
//!   config binds, and the workspace (RW, for `target/`) are mounted; the
//!   operator's HOME is a fresh tmpfs and the operator's Claude credentials are
//!   *not* overlaid (unlike the worker sandbox).
//!
//! The store-path `bwrap` pin ([`SandboxPin::verify`]) is checked fail-closed
//! *before* the child spawns. If it fails the gate refuses to run the script at
//! all (returning [`QaError::SandboxUnavailable`] poison) rather than fall back
//! to executing worker code unsandboxed on the host.
//!
//! ## What this closes — and the one axis it does NOT (scope honesty)
//!
//! Two *different* axes meet at `static_qa.sh`, and this P0 addresses exactly one:
//!
//! - **Execution axis (RCE / T1) — CLOSED here.** The concern is worker-authored
//!   `build.rs`/proc-macro/test code executing on the control plane with the
//!   orchestrator's env, network, and creds. Running that code in the box above
//!   is strictly *safer* than the status quo: the QA sandbox is **more**
//!   restrictive than the worker's own spawn sandbox (net denied, no creds
//!   overlay, no repo `.jj`/`.git`), so executing the worker's script inside it
//!   grants an attacker nothing they did not already have during implementation.
//!   That is the RCE gap, and it is shut.
//! - **Verdict-integrity axis — a KNOWN RESIDUAL, explicitly OUT of scope.**
//!   `static_qa.sh` is worker-authored and lives in the worker's RW workspace, so
//!   a malicious or lazy worker can rewrite it to `exit 0` and its QA gate passes
//!   unconditionally — the quality gate is neutered. The hermetic box does
//!   nothing about this and *cannot*: sandboxing execution is orthogonal to
//!   trusting the grader. Do **not** read "the script runs in a box now" as
//!   closing the grader-rewrite vector; it does not. The fix for that axis is to
//!   grade the committed tree with an **orchestrator-owned** script rather than
//!   the worker's copy (tracked as a P1), which this P0 deliberately does not
//!   attempt. Naming it here so the two axes are never conflated.
//!
//! [`SandboxPin::verify`]: crate::spawn::SandboxPin::verify
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
//! | sandbox unavailable   | `Err(SandboxUnavailable)` — poison         |
//!
//! The `SandboxUnavailable` row is raised in **two** places: *before* the child
//! spawns, when the `bwrap` store-path pin fails to verify (misconfigured
//! host/environment); and *after* the run, when the sandbox-handoff sentinel is
//! missing (see below). Both are anomalies the Implementer cannot fix, so they
//! are poison like every other `Err`.
//!
//! ### The exit-code channel is muxed — the sentinel handshake de-muxes it
//!
//! Wrapping the child as `env -i … bwrap … -- bash -c '…' <script>` does **not**
//! leave the exit code an untouched passthrough, and pretending it does is a
//! correctness bug. `bwrap` reports its *own* setup/exec failures — a missing
//! bind source, an unavailable net/user namespace on a hardened or nested host,
//! an unresolvable `bash` — as **exit 1**, the *same* code a faithful child
//! `exit 1` produces. Classifying that muxed 1 blindly would turn "the sandbox
//! never stood up" into a phantom `Fail { exit_code: 1 }` blocker, looping the
//! worker forever on a test failure that never happened. (The pin check does not
//! save us: it verifies `bwrap`'s binary *identity*, not this host's runtime
//! ability to create the namespaces `qa_mounts` demands.)
//!
//! So the gate de-muxes the channel with a **handshake sentinel**. The inner
//! command is `bash -c 'printf "%s\n" "<SENTINEL>"; exec bash "$0"' <script>`:
//! `bash` prints a fixed sentinel line to stdout *first*, then `exec`s
//! `bash <script>`. Because `exec` replaces the shell in place, the child's exit
//! code is **still the script's** — so once the sentinel is present, exit-code
//! classification is genuinely identical to the pre-sandbox behavior. After the
//! run, [`QaGate::run`] checks the *physical first line* of stdout:
//!
//! - **sentinel absent** ⇒ `bwrap` never handed off to `bash` (its own
//!   setup/exec failure) ⇒ [`QaError::SandboxUnavailable`] poison, naming the
//!   likely cause. The muxed exit 1 is never mistaken for a verdict.
//! - **sentinel present** ⇒ the sandbox handed off; strip that first line, then
//!   classify the exit code EXACTLY as below (`0`→Pass / `101`→Fail /
//!   `126`/`127`→poison / signal→Killed / timeout→TimedOut).
//!
//! This is **infrastructure detection, not verdict parsing**: it answers only
//! "did the sandbox hand off to bash", never "did QA pass". The module invariant
//! is preserved — the *verdict* is still derived purely from the exit code, never
//! from scanning output for a magic string. Printing the sentinel *before*
//! `exec` makes it always line 1, so a script that itself emits the sentinel text
//! can only do so on a later line and can never be confused for the handshake.
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
//! self-assessments). The one stdout inspection — the first-line handshake
//! sentinel — is *infrastructure* detection ("did bwrap hand off to bash"), not
//! verdict parsing: it can only turn a broken sandbox into poison, never a
//! script's output into a Pass/Fail.
//!
//! [`Fail`]: QaOutcome::Fail
//!
//! # No forbidden shell-out (AC-24)
//!
//! Running `.orchestrator/static_qa.sh` is the *sanctioned* AC-24 exception
//! (REQ-1a exception (b)): a user-supplied script is a shell contract, so it is
//! run via `bash <path>` — now `env -i … bwrap … -- bash -c '<handshake>; exec
//! bash "$0"' <path>` (the handshake prints the sandbox sentinel, then `exec`s
//! the script; see "The exit-code channel is muxed"). This is the one place the
//! orchestrator executes a user script; it is **not** a forbidden shell-out. No
//! `jj`/`git`/`gh`/`crosslink`/`zellij` subprocess is constructed here — the
//! no-shell-out lint bans exactly those names, and neither `bwrap` nor `bash` is
//! among them.
//!
//! # Known limitation: grandchild processes survive a kill
//!
//! On timeout the gate calls [`std::process::Child::kill`], which sends
//! `SIGKILL` to the direct child only. Any grandchildren the script spawned (a
//! `cargo` subprocess, its `rustc` invocations) are *not* reaped by the signal
//! itself — killing a whole process group needs a `setpgid` via `pre_exec`,
//! which is `unsafe` and this crate is `#![forbid(unsafe_code)]`.
//!
//! Sandboxing **blunts** this: the direct child is now `bwrap`, and
//! [`SandboxHost::qa_mounts`] runs it under `--unshare-pid`, so `bash`, `cargo`,
//! and `rustc` all live in a fresh PID namespace whose init is that `bwrap`.
//! When bwrap (PID 1 of that namespace) dies to our `SIGKILL`, the kernel tears
//! down the entire namespace — the grandchildren cannot survive their pid-ns
//! init. This improves the pre-sandbox "grandchildren survive" limitation for
//! free; the existing kill/reap loop is retained unchanged (it is still correct
//! and still what reaps the direct child).

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use vetinari_error::QaError;

use crate::spawn::{scrub_env_prefix, SandboxHost, SandboxPin};

/// The script the gate runs, relative to the workspace root (REQ-9). Committed
/// and whitelisted in the project's `.gitignore` (see the fixture). Kept as a
/// constant so the layout in `.design/vdd-orchestrator.md` and the code agree.
pub const STATIC_QA_SCRIPT: &str = ".orchestrator/static_qa.sh";

/// The **sandbox-handoff sentinel** the inner `bash` prints to stdout *before*
/// `exec`ing the QA script. Its presence as the physical first line of the
/// child's stdout is the proof that `bwrap` actually stood the sandbox up and
/// handed control to `bash` — see [`QaGate::run`] and the module's
/// "Exit-code classification" docs for why this is load-bearing.
///
/// A fixed, deliberately unlikely constant: a real `static_qa.sh` never prints
/// this, and even if it tried, our `printf` runs *first* (before `exec`), so the
/// sentinel is always line 1 and a script's own output can only ever appear on a
/// later line.
const SANDBOX_HANDOFF_SENTINEL: &str = "__VDD_QA_SANDBOX_HANDOFF_OK__";

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

/// The bwrap sandbox a [`QaGate`] runs its script inside: the resolved host
/// descriptor (mount policy) plus the store-path pin verified before every run.
///
/// Bundling the two keeps [`QaGate::run`] from resolving a fresh host deep in
/// its body — the pump, which already owns a [`SandboxPin`] via its spawner,
/// resolves the [`SandboxHost`] once and threads it in at construction.
#[derive(Debug, Clone)]
pub struct QaSandbox {
    /// The resolved sandbox host — supplies [`SandboxHost::qa_mounts`] and the
    /// pinned `bwrap` store path.
    host: SandboxHost,
    /// The store-path pin, verified fail-closed before each spawn.
    pin: SandboxPin,
}

impl QaSandbox {
    /// Bundle a resolved host with its pin.
    pub fn new(host: SandboxHost, pin: SandboxPin) -> Self {
        QaSandbox { host, pin }
    }
}

/// Runs the project's static QA script against a worker's workspace and returns
/// the orchestrator-owned verdict (REQ-9).
///
/// Holds the workspace root, a timeout, and (in production) the bwrap
/// [`QaSandbox`] the script is executed inside. [`run`](QaGate::run) resolves the
/// script relative to the root and executes it with that root as the working
/// directory — inside the hermetic, network-denied sandbox — so the QA tools see
/// exactly the tree the Implementer just committed while worker-authored
/// `build.rs`/test code cannot reach the host, and kills the child if it exceeds
/// the timeout.
#[derive(Debug, Clone)]
pub struct QaGate {
    /// The worker's workspace root — both the script's parent-of-parent and its
    /// working directory.
    workspace: PathBuf,
    /// Wall-clock budget before the gate kills the child (poison, not a Fail).
    timeout: Duration,
    /// The bwrap sandbox the script runs inside. `Some` on the production path
    /// ([`QaGate::new`]); `None` only on the in-crate unit-test seam
    /// ([`QaGate::new_unsandboxed`]), which runs bare `bash` to exercise the
    /// exit-code classification without requiring a live `bwrap`.
    sandbox: Option<QaSandbox>,
}

impl QaGate {
    /// A **sandboxed** gate over the worker's workspace root `workspace`, using
    /// [`DEFAULT_QA_TIMEOUT`]. The script is expected at
    /// `<workspace>/.orchestrator/static_qa.sh` and is executed inside `sandbox`
    /// (a hermetic, network-denied bwrap namespace — see the module docs). The
    /// production constructor: worker-authored QA code never runs on the host.
    pub fn new(workspace: impl Into<PathBuf>, sandbox: QaSandbox) -> Self {
        QaGate {
            workspace: workspace.into(),
            timeout: DEFAULT_QA_TIMEOUT,
            sandbox: Some(sandbox),
        }
    }

    /// An **unsandboxed** gate that runs bare `bash <script>` on the host — the
    /// in-crate test seam only.
    ///
    /// `pub(crate)` so it is unreachable from production callers (they must go
    /// through [`QaGate::new`] and get the sandbox): the exit-code-classification
    /// unit tests in this module test the *verdict* axis (Pass/Fail/poison from
    /// exit codes, tail capture, timeout), which is orthogonal to sandboxing, so
    /// they run on this bare path without needing a live `bwrap`. The security
    /// property (env/net/FS isolation surviving the wrapping) is proved
    /// separately by the bwrap-gated integration test in `tests/qa_gate.rs`.
    #[cfg(test)]
    pub(crate) fn new_unsandboxed(workspace: impl Into<PathBuf>) -> Self {
        QaGate {
            workspace: workspace.into(),
            timeout: DEFAULT_QA_TIMEOUT,
            sandbox: None,
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
    /// Executes the worker's `<workspace>/.orchestrator/static_qa.sh` **inside a
    /// hermetic bwrap sandbox** — `env -i <allowlist> <pinned-bwrap>
    /// <qa_mounts…> -- bash <script>` — with `<workspace>` as the (in-sandbox)
    /// working directory, draining combined stdout+stderr into a byte-bounded
    /// buffer (at most [`MAX_CAPTURE_BYTES`], tail kept). On the sandboxed path it
    /// then checks the **sandbox-handoff sentinel** (module docs, "The exit-code
    /// channel is muxed"): if the inner `bash` never printed it, `bwrap`'s own
    /// setup/exec failure muxed into exit 1 rather than a script verdict, so the
    /// run is [`QaError::SandboxUnavailable`] poison. Once the sentinel is present
    /// (stripped from the captured stdout), the verdict is derived from the exit
    /// status per the classification table — the `exec` in the handshake means the
    /// child's exit code is the inner `bash <script>`'s, identical to pre-sandbox:
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
    /// - `bash`/`bwrap` is missing or the path is unreachable so the child cannot
    ///   even be spawned → [`QaError::ScriptUnspawnable`],
    /// - the `bwrap` store-path pin fails to verify (missing/mismatched `bwrap`),
    ///   or `bwrap` could not stand the sandbox up (handshake sentinel absent) →
    ///   [`QaError::SandboxUnavailable`] (the pin is checked before spawning and
    ///   the handshake after; either way the gate refuses to route a sandbox
    ///   failure to a phantom `Fail`).
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

        // Assemble the child argv. On the production path this is the sandboxed
        // form `env -i <allowlist> <bwrap> <qa_mounts…> -- bash <script>`: the
        // `env -i` scrub and the hermetic bwrap namespace mean the
        // worker-authored code the script compiles/runs (`build.rs`, tests) can
        // reach neither the orchestrator's env (no `GH_TOKEN`) nor the network nor
        // the host FS (P0, closes T1). The `bwrap` binary is the *pinned* store
        // path (verified fail-closed just below), never a bare `bwrap`. The
        // in-crate test seam (`new_unsandboxed`) runs bare `bash <script>` — the
        // pre-sandbox behavior — to exercise exit-code classification without a
        // live bwrap.
        let argv = match &self.sandbox {
            Some(sb) => {
                // Store-path pin guard (REQ-4a / AC-19), BEFORE spawning: refuse
                // to run worker code if the `bwrap` on PATH is not the exact
                // pinned build. A pin failure is a host/environment misconfig, so
                // it is POISON (SandboxUnavailable) — never a fallback to running
                // the script unsandboxed on the host.
                sb.pin
                    .verify()
                    .map_err(|source| QaError::SandboxUnavailable {
                        reason: source.to_string(),
                    })?;
                let mut argv = scrub_env_prefix(&[]);
                argv.push(sb.pin.expected().to_owned());
                argv.extend(sb.host.qa_mounts(&self.workspace));
                argv.push("--".to_owned());
                // The sandbox-handoff handshake (see the module's "Exit-code
                // classification" docs). The inner `bash -c` prints the sentinel
                // to stdout FIRST, then `exec`s `bash <script>` — `exec` replaces
                // the shell, so the child's exit code is STILL the script's
                // (classification is genuinely preserved). The script path rides
                // as `$0` so it stays a real argv entry, not string-interpolated.
                // If bwrap's own setup/exec fails, the sentinel is never printed
                // and `run` returns `SandboxUnavailable` instead of misreading
                // bwrap's exit 1 as a QA `Fail`.
                argv.push("bash".to_owned());
                argv.push("-c".to_owned());
                argv.push(format!(
                    "printf '%s\\n' '{SANDBOX_HANDOFF_SENTINEL}'; exec bash \"$0\""
                ));
                argv.push(script.to_string_lossy().into_owned());
                argv
            }
            None => vec!["bash".to_owned(), script.to_string_lossy().into_owned()],
        };

        // The AC-24-sanctioned shell-out: a user-supplied script is a shell
        // contract (REQ-1a exception (b)). stdout and stderr are piped and
        // drained concurrently (below) so a runaway script can't deadlock on a
        // full pipe buffer. `.current_dir` sets the *outer* cwd; inside the
        // sandbox `--chdir <workspace>` (from `qa_mounts`) governs, so QA tools
        // see the tree the Implementer committed either way.
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
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

        // Sandbox-handoff detection (infrastructure, NOT verdict parsing). On the
        // production path bwrap muxes its OWN setup/exec failures (missing bind
        // source, unavailable netns/userns, unresolvable `bash`) into exit 1 —
        // the SAME channel a faithful child `exit 1` uses. So before classifying,
        // require the handshake sentinel the inner `bash` prints *before* `exec`:
        // if it is the physical first line of stdout, the sandbox handed off to
        // bash and the exit code is genuinely the script's (strip the sentinel,
        // then classify EXACTLY as the unsandboxed path). If it is absent, bwrap
        // never stood the sandbox up — that is `SandboxUnavailable` poison, not a
        // phantom QA `Fail`. This detects "did the sandbox hand off to bash",
        // never "did QA pass" — the verdict still comes purely from the exit code.
        let stdout = if self.sandbox.is_some() {
            match strip_handoff_sentinel(&stdout) {
                Some(script_stdout) => script_stdout,
                None => {
                    return Err(QaError::SandboxUnavailable {
                        reason: format!(
                            "bwrap did not hand off to bash: the sandbox setup/exec \
                             failed before the handshake sentinel was printed (bwrap \
                             muxes this into the same exit code as a script failure). \
                             Likely the host cannot create the required namespaces \
                             (--unshare-net/--unshare-pid/--proc/--dev) under an \
                             unprivileged user, or a bind source is missing at spawn \
                             time. bwrap stderr tail:\n{}",
                            OutputTail::from_output(&String::from_utf8_lossy(&stderr)).0
                        ),
                    });
                }
            }
        } else {
            stdout
        };

        classify(&status, stdout, stderr)
    }
}

/// If `stdout`'s physical first line is exactly the [`SANDBOX_HANDOFF_SENTINEL`],
/// return the remaining stdout with that first line removed; otherwise `None`.
///
/// The sentinel is printed by the inner `bash` *before* it `exec`s the script, so
/// a successful sandbox handoff always makes it byte-for-byte the start of the
/// stream followed by a newline. Requiring the very next byte to be `\n` means a
/// script that itself emits a line merely *beginning* with the sentinel text
/// cannot be mistaken for the handshake — and since our `printf` runs first, the
/// script's own output can only ever land on a later line anyway.
fn strip_handoff_sentinel(stdout: &[u8]) -> Option<Vec<u8>> {
    let rest = stdout.strip_prefix(SANDBOX_HANDOFF_SENTINEL.as_bytes())?;
    match rest.first() {
        // Sentinel followed by its newline: the script's stdout is everything
        // after that newline.
        Some(b'\n') => Some(rest[1..].to_vec()),
        // Sentinel is the entire stdout (script produced nothing on stdout).
        None => Some(Vec::new()),
        // First line is `<sentinel><something-else>` — not our handshake line.
        Some(_) => None,
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
        let outcome = QaGate::new_unsandboxed(&root).run().expect("gate runs");
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
        let outcome = QaGate::new_unsandboxed(&root)
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
            QaGate::new_unsandboxed(&r1).run().expect("runs"),
            QaOutcome::Fail { .. }
        ));

        let (_t2, r2) = workspace_with_script("#!/usr/bin/env bash\necho FAIL\nexit 0\n");
        assert_eq!(
            QaGate::new_unsandboxed(&r2).run().expect("runs"),
            QaOutcome::Pass
        );
    }

    /// A real QA-tool exit code like `101` (cargo test) stays a `Fail`, not
    /// poison — only 126/127 are the broken-gate codes.
    #[test]
    fn tool_exit_101_is_fail_not_poison() {
        let (_tmp, root) = workspace_with_script("#!/usr/bin/env bash\nexit 101\n");
        let outcome = QaGate::new_unsandboxed(&root)
            .run()
            .expect("101 is a routine Fail");
        assert!(matches!(outcome, QaOutcome::Fail { exit_code: 101, .. }));
    }

    // --- Poison: broken-gate exit codes 126 / 127 ---------------------------

    /// Exit 127 (command-not-found inside the script, e.g. `cargo` missing) is a
    /// broken gate → `ScriptItselfErrored` poison, never a blocker `Fail`.
    #[test]
    fn exit_127_command_not_found_is_poison() {
        let (_tmp, root) =
            workspace_with_script("#!/usr/bin/env bash\ndefinitely-not-a-real-command-xyzzy\n");
        let err = QaGate::new_unsandboxed(&root).run().unwrap_err();
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
        let err = QaGate::new_unsandboxed(&root).run().unwrap_err();
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
        let err = QaGate::new_unsandboxed(&root).run().unwrap_err();
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
        let err = QaGate::new_unsandboxed(&root)
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
        let outcome = QaGate::new_unsandboxed(&root).run().expect("runs");
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
        let QaOutcome::Fail { output_tail, .. } =
            QaGate::new_unsandboxed(&root).run().expect("runs")
        else {
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
        let QaOutcome::Fail { output_tail, .. } =
            QaGate::new_unsandboxed(&root).run().expect("runs")
        else {
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
        let err = QaGate::new_unsandboxed(&root).run().unwrap_err();
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

        let result = QaGate::new_unsandboxed(&root).run();

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

    // --- Sandbox-handoff sentinel -------------------------------------------

    /// The sentinel is stripped only when it is the exact physical first line;
    /// its absence (a bwrap setup/exec failure) is signalled by `None`, which
    /// `run` maps to `SandboxUnavailable` poison.
    #[test]
    fn strip_handoff_sentinel_distinguishes_handoff_from_failure() {
        let s = SANDBOX_HANDOFF_SENTINEL;

        // Sentinel line then the script's real stdout: stripped to just the rest.
        let stdout = format!("{s}\nreal script output\nmore\n").into_bytes();
        assert_eq!(
            strip_handoff_sentinel(&stdout),
            Some(b"real script output\nmore\n".to_vec())
        );

        // Sentinel is the whole stdout (script printed nothing): empty rest.
        let only = format!("{s}\n").into_bytes();
        assert_eq!(strip_handoff_sentinel(&only), Some(Vec::new()));

        // Sentinel with no trailing newline and nothing else: still a handoff.
        assert_eq!(strip_handoff_sentinel(s.as_bytes()), Some(Vec::new()));

        // bwrap setup/exec failure: stdout empty or missing the sentinel → None.
        assert_eq!(strip_handoff_sentinel(b""), None);
        assert_eq!(strip_handoff_sentinel(b"bwrap: something failed\n"), None);

        // A first line that merely BEGINS with the sentinel text is NOT the
        // handshake (our printf always makes it a whole line on its own).
        let impostor = format!("{s}-not-really\n").into_bytes();
        assert_eq!(strip_handoff_sentinel(&impostor), None);
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
