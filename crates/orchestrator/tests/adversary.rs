//! Integration tests for the Adversary role's orchestrator-side input
//! pre-rendering and the spawn/parse round-trip (A1, REQ-8).
//!
//! - **Pre-rendering** — against a real `build_fixture()` repo with a committed
//!   Implementer change, [`orchestrator::roles::adversary::render_inputs`]
//!   writes `_orchestrator/{diff.patch, log.txt, prior_findings.json, task.md}`
//!   with the expected content: the diff carries the change's actual diff, the
//!   log is non-empty, and `prior_findings.json` is a valid JSON array (`[]`
//!   when there are no prior rounds, populated otherwise).
//! - **Round-trip** — the committed `fake-adversary.sh`, run in a workspace the
//!   orchestrator pre-rendered inputs into, reads `diff.patch` and writes a
//!   canned `findings.jsonl` + DONE that S3's [`orchestrator::artifacts`]
//!   parsers consume, proving the pre-render → Adversary → parse loop closes
//!   without a live `claude`.
//!
//! These drive the real `jj` CLI through the test harness (the AC-24
//! no-shell-out lint scopes to `src/**` only).

mod common;

use std::path::Path;
use std::process::Command;

use orchestrator::artifacts::{DoneSentinel, Findings, Severity};
use orchestrator::roles::adversary::{
    render_inputs, RenderParams, DIFF_FILE, LOG_FILE, PRIOR_FINDINGS_FILE, TASK_FILE,
};
use orchestrator::workspace::WorkspaceManager;

use common::{
    build_fixture, fake_adversary, fake_adversary_clean, fake_adversary_no_findings,
    fake_implementer,
};

/// The change id of `@` in the repo rooted at `cwd` (test-support read).
fn wc_change_id(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["log", "-r", "@", "--no-graph", "-T", "change_id"])
        .current_dir(cwd)
        .output()
        .expect("jj log for change id");
    assert!(out.status.success(), "jj log failed");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Run `program args...` in `cwd`, panicking with captured output on failure.
fn run(program: &str, args: &[&str], cwd: &Path) {
    let out = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("spawn `{program}`: {e}"));
    assert!(
        out.status.success(),
        "`{program} {}` failed:\n{}\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// A committed Implementer change on top of `main`: the fixture (held for its
/// lifetime), the manager over its repo, and the change's revset. Shared setup.
fn stage_change() -> (common::Fixture, WorkspaceManager, String) {
    let fx = build_fixture();
    let manager = WorkspaceManager::load(&fx.root).expect("load repo into gate");
    // The Implementer edits src/lib.rs (appends say_hi) and commits on `@`.
    run("bash", &[fake_implementer().to_str().unwrap()], &fx.root);
    let change = wc_change_id(&fx.root);
    (fx, manager, change)
}

#[test]
fn render_inputs_writes_the_four_files_with_expected_content() {
    let (_fx, manager, change) = stage_change();
    let ws = tempfile::tempdir().expect("workspace tempdir");

    let params = RenderParams {
        diff_from: &format!("{change}-"),
        diff_to: &change,
        log_revset: &change,
        prior_findings: &[],
        task: "# Add say_hi\n\nAdd a greeting helper.",
    };
    render_inputs(&manager, ws.path(), &params).expect("pre-render succeeds");

    let art = ws.path().join("_orchestrator");

    // diff.patch carries the actual change diff (say_hi added to src/lib.rs).
    let patch = std::fs::read_to_string(art.join(DIFF_FILE)).expect("diff.patch written");
    assert!(
        patch.contains("diff --git") && patch.contains("say_hi"),
        "diff.patch must contain the change's diff, got:\n{patch}"
    );
    assert!(
        patch.contains("src/lib.rs"),
        "diff.patch must name the edited file:\n{patch}"
    );

    // log.txt is non-empty and names the change.
    let log = std::fs::read_to_string(art.join(LOG_FILE)).expect("log.txt written");
    assert!(!log.trim().is_empty(), "log.txt must be non-empty");
    assert!(log.contains("commit "), "log.txt stanza shape: {log}");

    // prior_findings.json is a valid JSON array — empty here (no prior rounds).
    let prior = std::fs::read_to_string(art.join(PRIOR_FINDINGS_FILE)).expect("prior written");
    let val: serde_json::Value = serde_json::from_str(&prior).expect("prior is valid JSON");
    assert!(
        val.is_array(),
        "prior_findings.json must be an array: {prior}"
    );
    assert_eq!(val.as_array().unwrap().len(), 0, "no prior rounds → []");

    // task.md is the verbatim task.
    let task = std::fs::read_to_string(art.join(TASK_FILE)).expect("task.md written");
    assert!(task.contains("Add say_hi"), "task.md content: {task}");
}

#[test]
fn render_inputs_serializes_prior_findings_in_findings_schema() {
    let (_fx, manager, change) = stage_change();
    let ws = tempfile::tempdir().expect("workspace tempdir");

    // A prior round's findings, parsed from a findings.jsonl body.
    let prior_body = r#"{"severity":"high","location":"src/lib.rs:3","claim":"panics on empty input","evidence_files":["src/lib.rs"]}"#;
    let prior = Findings::parse(Path::new("prior.jsonl"), prior_body).expect("parse prior");

    let params = RenderParams {
        diff_from: &format!("{change}-"),
        diff_to: &change,
        log_revset: &change,
        prior_findings: prior.findings(),
        task: "# task",
    };
    render_inputs(&manager, ws.path(), &params).expect("pre-render succeeds");

    let prior_json =
        std::fs::read_to_string(ws.path().join("_orchestrator").join(PRIOR_FINDINGS_FILE))
            .expect("prior written");
    // Valid array, carrying the flat `path:line` location the Adversary reads.
    let val: serde_json::Value = serde_json::from_str(&prior_json).expect("valid JSON");
    let arr = val.as_array().expect("array");
    assert_eq!(arr.len(), 1, "one prior finding: {prior_json}");
    assert_eq!(arr[0]["severity"], "high");
    assert_eq!(arr[0]["location"], "src/lib.rs:3");
    assert_eq!(arr[0]["claim"], "panics on empty input");
}

#[test]
fn fake_adversary_round_trip_produces_parseable_findings_and_done() {
    let (_fx, manager, change) = stage_change();
    let ws = tempfile::tempdir().expect("adversary workspace tempdir");

    // Orchestrator pre-renders the Adversary's inputs (as before the spawn).
    let params = RenderParams {
        diff_from: &format!("{change}-"),
        diff_to: &change,
        log_revset: &change,
        prior_findings: &[],
        task: "# Add say_hi",
    };
    render_inputs(&manager, ws.path(), &params).expect("pre-render succeeds");

    // The Adversary worker runs in that workspace, reading diff.patch and
    // writing findings.jsonl + result.md + DONE (mirrors a Direct-worker
    // dispatch, sans zellij).
    run("bash", &[fake_adversary().to_str().unwrap()], ws.path());

    // S3's DONE gate verifies the worker finished cleanly and both artifacts
    // hash-match what DONE recorded.
    let done = DoneSentinel::verify(ws.path()).expect("Adversary DONE verifies");
    assert_eq!(done.artifacts().len(), 2, "findings.jsonl + result.md");

    // S3's findings parser consumes the real Adversary output.
    let art = ws.path().join("_orchestrator");
    let findings = Findings::read(&art).expect("findings parse");
    assert_eq!(findings.findings().len(), 1, "one canned finding");
    let f = &findings.findings()[0];
    assert_eq!(f.severity, Severity::Med);
    // The finding cites the file the pre-rendered diff touched (proves the
    // worker consumed its input).
    assert_eq!(f.location.path(), "src/lib.rs");
}

/// The strict convergence reader accepts an Adversary that wrote an EMPTY but
/// DONE-declared `findings.jsonl`: a valid clean/converged round (REQ-10).
#[test]
fn fake_adversary_empty_declared_findings_is_a_clean_round() {
    let (_fx, manager, change) = stage_change();
    let ws = tempfile::tempdir().expect("adversary workspace tempdir");

    let params = RenderParams {
        diff_from: &format!("{change}-"),
        diff_to: &change,
        log_revset: &change,
        prior_findings: &[],
        task: "# Add say_hi",
    };
    render_inputs(&manager, ws.path(), &params).expect("pre-render succeeds");

    // The Adversary found nothing: empty findings.jsonl, declared in DONE.
    run(
        "bash",
        &[fake_adversary_clean().to_str().unwrap()],
        ws.path(),
    );

    let done = DoneSentinel::verify(ws.path()).expect("clean-round DONE verifies");
    // The strict reader treats the empty-but-declared file as a clean round.
    let findings = Findings::from_done(&done).expect("empty-declared is a clean round");
    assert!(
        findings.is_empty(),
        "an empty declared findings.jsonl converges"
    );
}

/// The load-bearing gap: an Adversary that wrote DONE but never produced
/// `findings.jsonl` must NOT read as converged. `DoneSentinel::verify` passes
/// (it only validates declared artifacts), and the lenient `Findings::read`
/// would (wrongly) call it empty — but the strict `Findings::from_done` rejects
/// it as an incomplete round so the convergence loop re-spawns, not auto-lands.
#[test]
fn fake_adversary_missing_findings_is_not_converged() {
    let (_fx, manager, change) = stage_change();
    let ws = tempfile::tempdir().expect("adversary workspace tempdir");

    let params = RenderParams {
        diff_from: &format!("{change}-"),
        diff_to: &change,
        log_revset: &change,
        prior_findings: &[],
        task: "# Add say_hi",
    };
    render_inputs(&manager, ws.path(), &params).expect("pre-render succeeds");

    // A crashed Adversary: DONE written, but no findings.jsonl.
    run(
        "bash",
        &[fake_adversary_no_findings().to_str().unwrap()],
        ws.path(),
    );

    // The DONE gate itself passes — it validates only the artifacts DONE names.
    let done = DoneSentinel::verify(ws.path()).expect("DONE (result.md only) verifies");

    // The lenient reader is the hole: it maps the absent file to empty.
    let art = ws.path().join("_orchestrator");
    assert!(
        Findings::read(&art).expect("lenient read").is_empty(),
        "lenient read maps the absent file to empty — the hole being closed"
    );

    // The strict convergence reader refuses it: incomplete round, not clean.
    let err = Findings::from_done(&done).expect_err("strict reader must reject absent findings");
    assert!(
        matches!(err, vetinari_error::ArtifactError::FindingsMissing { .. }),
        "absent findings.jsonl must be FindingsMissing, got {err:?}"
    );
}
