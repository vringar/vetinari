//! Fixture-backed static QA gate tests (REQ-9, AC-7).
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
//! The poison case (missing script) and the tail-capping / exit-code-vs-string
//! invariants are proved by the fast in-module unit tests in `src/qa.rs`; these
//! integration tests exercise the real `bash` + `cargo` shell-out end to end.

mod common;

use common::build_fixture;
use orchestrator::qa::{QaGate, QaOutcome, TAIL_LINES};

/// AC-7 pass: the fixture's baseline `cargo test` succeeds, so the gate — which
/// runs the committed `static_qa.sh` (`cargo test --locked --offline`) with the
/// workspace as cwd — returns `Pass`.
#[test]
fn fixture_baseline_qa_passes() {
    let fx = build_fixture();
    let outcome = QaGate::new(&fx.root)
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
    let fx = build_fixture();

    // Introduce a hard compile error into the crate the committed `static_qa.sh`
    // builds. `cargo test --locked --offline` will fail to compile and exit
    // non-zero — exactly a QA tool saying no.
    let lib = fx.root.join("src/lib.rs");
    let mut src = std::fs::read_to_string(&lib).expect("read fixture lib.rs");
    src.push_str("\nthis is not valid rust and will not compile;\n");
    std::fs::write(&lib, src).expect("write broken lib.rs");

    let outcome = QaGate::new(&fx.root)
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
