//! Fixture-backed static QA gate tests (REQ-9, AC-7) + the P0 sandbox security
//! property (threat model §1c / T1).
//!
//! These drive [`QaGate`] against a real dogfood workspace produced by
//! [`build_fixture`], whose committed `.orchestrator/static_qa.sh` runs
//! `cargo test --locked --offline` over the `hello` crate. Two ends of AC-7:
//!
//! - **pass:** the fixture's baseline crate compiles and its tests pass, so the
//!   gate returns `Pass`.
//! - **fail:** breaking the crate so `cargo test` fails makes the gate return
//!   `Fail { exit_code, output_tail }` with the compiler output in the tail —
//!   and never a poison `Err`. This is the AC-7 blocker path (a fixture that
//!   fails QA keeps the issue at `phase:implementing` with a blocker comment).
//!
//! **The gate now runs the script inside a hermetic bwrap sandbox** (P0 fix):
//! worker-authored `build.rs`/test code never executes on the host. These tests
//! therefore exercise the *production* sandboxed path end to end and are gated
//! on a live, pinned `bwrap` (they `return` early — skip — when `bwrap` cannot
//! be verified, mirroring the isolation tests in `spawn_dispatch.rs`). The
//! exit-code classification unit tests (Pass/Fail/poison/tail/timeout) run on
//! the bare `new_unsandboxed` seam in `src/qa.rs` and need no `bwrap`.
//!
//! The final test proves the security property directly: with crafted scripts it
//! asserts the sandbox scrubs the env (no `GH_TOKEN`), denies host network
//! egress, hides the host filesystem, AND that the exit-code→verdict
//! classification still holds through the bwrap wrapping.

mod common;

use common::build_fixture;
use orchestrator::qa::{QaGate, QaOutcome, QaSandbox, TAIL_LINES};
use orchestrator::spawn::{SandboxHost, SandboxPin};

use std::time::Duration;

/// Resolve the live `bwrap` pin for the sandboxed gate: the shell's
/// `VDD_BWRAP_PIN` if set, else the first `bwrap` on `PATH`. Mirrors
/// `spawn_dispatch.rs::resolve_bwrap`.
fn resolve_bwrap() -> String {
    if let Some(pin) = std::env::var("VDD_BWRAP_PIN")
        .ok()
        .filter(|p| !p.is_empty())
    {
        return pin;
    }
    let path_env = std::env::var("PATH").unwrap_or_default();
    std::env::split_paths(&path_env)
        .map(|d| d.join("bwrap"))
        .find(|p| p.exists())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "bwrap".to_owned())
}

/// Build the production [`QaSandbox`] from the live environment, or `None` when
/// `bwrap` cannot be verified (unavailable outside the dev shell) — the caller
/// then skips, exactly like the `spawn_dispatch.rs` isolation tests require a
/// live `bwrap`. `verify()` is the same fail-closed pin guard `QaGate::run`
/// runs, so a `Some` here means the sandboxed spawn can proceed.
fn sandbox_or_skip() -> Option<QaSandbox> {
    let pin = SandboxPin::new(resolve_bwrap());
    if pin.verify().is_err() {
        eprintln!("skipping: no verifiable `bwrap` pin (set VDD_BWRAP_PIN in the dev shell)");
        return None;
    }
    // The QA gate resolves via `resolve_for_qa` in production (no `nix-shell`
    // dependency, no creds overlay) — mirror that here so the test exercises the
    // real path.
    let host = SandboxHost::resolve_for_qa(&pin).expect("resolve QA sandbox host (HOME present)");
    Some(QaSandbox::new(host, pin))
}

/// AC-7 pass: the fixture's baseline `cargo test` succeeds, so the gate — which
/// runs the committed `static_qa.sh` (`cargo test --locked --offline`) *inside
/// the sandbox* with the workspace as cwd — returns `Pass`.
#[test]
fn fixture_baseline_qa_passes() {
    let Some(sandbox) = sandbox_or_skip() else {
        return;
    };
    let fx = build_fixture();
    let outcome = QaGate::new(&fx.root, sandbox)
        .run()
        .expect("QA gate must run on the fixture, not error");
    assert_eq!(
        outcome,
        QaOutcome::Pass,
        "the fixture's baseline crate compiles and tests pass, so QA must pass"
    );
}

/// AC-7 fail: breaking the crate so it no longer compiles makes `cargo test`
/// exit non-zero, so the gate returns `Fail` carrying the exit code and a tail
/// with the compiler's rejection — a routine blocker, never poison.
#[test]
fn broken_crate_qa_fails_with_compiler_output() {
    let Some(sandbox) = sandbox_or_skip() else {
        return;
    };
    let fx = build_fixture();

    // Introduce a hard compile error into the crate the committed `static_qa.sh`
    // builds. `cargo test --locked --offline` will fail to compile and exit
    // non-zero — exactly a QA tool saying no.
    let lib = fx.root.join("src/lib.rs");
    let mut src = std::fs::read_to_string(&lib).expect("read fixture lib.rs");
    src.push_str("\nthis is not valid rust and will not compile;\n");
    std::fs::write(&lib, src).expect("write broken lib.rs");

    let outcome = QaGate::new(&fx.root, sandbox)
        .run()
        .expect("a failing QA tool is Ok(Fail), never Err poison");

    match outcome {
        QaOutcome::Fail {
            exit_code,
            output_tail,
        } => {
            assert_ne!(
                exit_code, 0,
                "a failed compile must carry a non-zero exit code, got {exit_code}"
            );
            // The tail carries the failing transcript for the blocker body, and
            // is capped at the line budget.
            assert!(
                output_tail.line_count() <= TAIL_LINES,
                "tail must be capped at TAIL_LINES, got {}",
                output_tail.line_count()
            );
            assert!(
                output_tail.as_str().contains("error"),
                "the tail must contain the compiler's error output, got:\n{}",
                output_tail.as_str()
            );
        }
        QaOutcome::Pass => panic!("a non-compiling crate must fail QA"),
    }
}

// ============================================================================
// P0 sandbox security property (threat model §1c / T1)
// ============================================================================

/// Materialize a workspace with a `.orchestrator/static_qa.sh` whose body is
/// `body`, marked executable. Returns the tempdir (hold it) and its root.
fn workspace_with_script(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let dir = root.join(".orchestrator");
    std::fs::create_dir_all(&dir).expect("mkdir .orchestrator");
    let script = dir.join("static_qa.sh");
    std::fs::write(&script, body).expect("write static_qa.sh");
    let mut perms = std::fs::metadata(&script).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script, perms).expect("chmod +x");
    (tmp, root)
}

/// The load-bearing security test (P0, closes T1). A crafted `static_qa.sh`
/// asserts, from *inside* the sandbox, the three isolation properties the fix
/// establishes; a fourth pair of scripts proves the exit-code→verdict
/// classification still holds through the bwrap wrapping.
///
/// (a) **env scrubbed** — `GH_TOKEN=sentinel` is set in *this* process's env, but
///     the child runs under `env -i PATH/HOME/TERM`, so `$GH_TOKEN` is empty
///     inside. A `PATH` sanity check makes the env assertion non-vacuous (the
///     script *can* see forwarded vars; `GH_TOKEN` is specifically scrubbed).
/// (b) **network denied** — `--unshare-net` gives the child a *fresh* net
///     namespace whose only interface is loopback. The probe reads
///     `/proc/net/dev` (always present via `--proc`; `/sys` is not mounted) and
///     asserts the only interface is `lo`. This depends on the SANDBOX, not on
///     the host: a shared/open net namespace would expose the host's `eth0`/etc.
///     — unlike a `/dev/tcp` egress probe, which passes vacuously on an
///     egress-less CI runner where the host itself cannot connect. It also
///     asserts `lo` IS present, so it can't pass vacuously on an unreadable file.
/// (c) **host FS denied** — a sentinel file created under the orchestrator's real
///     `$HOME` (outside the workspace and `/nix`) is invisible: `$HOME` is a
///     fresh tmpfs inside the sandbox.
///
/// Property (a)+(b)+(c) are folded into one script that exits `0` only if *every*
/// isolation holds (each leak takes a distinct non-zero exit), so a green `Pass`
/// is the conjunction of all three.
#[test]
fn qa_sandbox_scrubs_env_denies_net_and_hides_host_fs() {
    let Some(sandbox) = sandbox_or_skip() else {
        return;
    };

    // (a) A secret in the orchestrator's env that MUST NOT reach worker code.
    std::env::set_var("GH_TOKEN", "sentinel-must-not-leak");

    // (c) A sentinel under the orchestrator's real HOME, outside any mount the
    // sandbox exposes. It must be invisible inside the namespace.
    let home = std::env::var("HOME").expect("HOME set");
    let sentinel = std::path::Path::new(&home).join(format!(
        ".vetinari_qa_host_fs_sentinel_{}",
        std::process::id()
    ));
    std::fs::write(&sentinel, b"host-fs-secret").expect("write host sentinel");
    // Cleaned up on all paths below.
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _guard = Cleanup(sentinel.clone());

    let body = format!(
        r#"#!/usr/bin/env bash
# Sanity: PATH IS forwarded, so an empty GH_TOKEN is real scrubbing, not an
# entirely empty environment that would make (a) vacuous.
if [ -z "$PATH" ]; then echo "no PATH: env check vacuous" >&2; exit 45; fi
# (a) env scrubbed — GH_TOKEN from the orchestrator's env must not be visible.
if [ -n "$GH_TOKEN" ]; then echo "LEAK env GH_TOKEN=$GH_TOKEN" >&2; exit 42; fi
# (c) host FS denied — the sentinel under the operator's HOME must be invisible.
if [ -e "{sentinel}" ]; then echo "LEAK host-fs: {sentinel} visible" >&2; exit 44; fi
# (b) network denied — a fresh net namespace (--unshare-net) has ONLY loopback.
# Read /proc/net/dev (present via --proc; no external tool, pure-bash parse) and
# assert the sole interface is `lo`. This depends on the sandbox, not on whether
# the host has egress. `saw_lo` guards against a vacuous pass on an empty file.
if [ ! -r /proc/net/dev ]; then echo "cannot read /proc/net/dev: net check vacuous" >&2; exit 46; fi
saw_lo=0
while IFS= read -r line; do
    case "$line" in
        *:*)
            iface=${{line%%:*}}
            iface=${{iface// /}}
            if [ "$iface" = "lo" ]; then
                saw_lo=1
            elif [ -n "$iface" ]; then
                echo "LEAK net iface '$iface' visible (net ns shared with host)" >&2; exit 43
            fi
            ;;
    esac
done < /proc/net/dev
if [ "$saw_lo" -ne 1 ]; then echo "no lo in /proc/net/dev: net check vacuous" >&2; exit 46; fi
exit 0
"#,
        sentinel = sentinel.display(),
    );
    let (_tmp, root) = workspace_with_script(&body);

    let outcome = QaGate::new(&root, sandbox)
        .with_timeout(Duration::from_secs(120))
        .run()
        .expect("the isolation probe must run to completion, not poison");
    assert_eq!(
        outcome,
        QaOutcome::Pass,
        "sandbox isolation breached — one of env(42)/net-iface(43)/host-fs(44)/\
         no-PATH-vacuous(45)/net-check-vacuous(46) fired; a Pass is the \
         conjunction of all isolation properties holding"
    );
}

/// (d) The exit-code→verdict classification survives the bwrap wrapping: a
/// script that `exit 101` inside the sandbox still yields `Fail { exit_code:
/// 101 }`, and `exit 0` yields `Pass`. Proves the verdict logic is unchanged by
/// running the child as `env -i … bwrap … -- bash <script>`.
#[test]
fn qa_sandbox_preserves_exit_code_classification() {
    let Some(sandbox) = sandbox_or_skip() else {
        return;
    };

    // exit 101 (the canonical `cargo test` failure code) → Fail { 101 }.
    let (_t1, r1) = workspace_with_script("#!/usr/bin/env bash\nexit 101\n");
    let fail = QaGate::new(&r1, sandbox.clone())
        .with_timeout(Duration::from_secs(60))
        .run()
        .expect("exit 101 is a routine Fail through the sandbox, not poison");
    assert!(
        matches!(fail, QaOutcome::Fail { exit_code: 101, .. }),
        "exit 101 must classify as Fail {{ exit_code: 101 }} through bwrap, got {fail:?}"
    );

    // exit 0 → Pass.
    let (_t2, r2) = workspace_with_script("#!/usr/bin/env bash\nexit 0\n");
    let pass = QaGate::new(&r2, sandbox)
        .with_timeout(Duration::from_secs(60))
        .run()
        .expect("exit 0 runs cleanly through the sandbox");
    assert_eq!(
        pass,
        QaOutcome::Pass,
        "exit 0 must classify as Pass through bwrap"
    );
}
