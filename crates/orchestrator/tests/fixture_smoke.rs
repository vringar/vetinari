//! Smoke tests for the dogfood fixture scaffolding (part of #19 / AC-11a).
//!
//! These prove the two pieces the vertical tracer-bullet build stands on.
//!
//! First, `build_fixture()` produces a repository the orchestrator's own
//! `crosslink_api` can open, read, and sign against. Second,
//! `fake-implementer.sh` honors the Implementer artifact contract (REQ-3b): it
//! edits the crate, commits via `jj describe`, and writes `result.md` followed
//! by the `DONE` sentinel.
//!
//! The full `graphed -> merged` loop is wired in later issues (S2, pump, QA,
//! landing); these keep the scaffolding honest in the meantime.

mod common;

use std::process::Command;

use common::{build_fixture, fake_implementer};
use vetinari_crosslink_api::CrosslinkRepo;

#[test]
fn fixture_is_readable_by_crosslink_api() {
    let fx = build_fixture();

    let repo = CrosslinkRepo::open(&fx.root).expect("open the fixture crosslink repo");
    let issue = repo.read_issue(fx.issue_id).expect("read the seed issue");

    assert!(
        issue.title.contains("say_hi"),
        "seed issue title should name the task, got {:?}",
        issue.title
    );
    assert_eq!(issue.status, "open");
    assert!(
        issue.labels.iter().any(|l| l == "phase:graphed"),
        "seed issue must be pre-graphed so the build pump picks it up, got {:?}",
        issue.labels
    );

    // AC-16 (later) signs orchestrator writes; the fixture must carry a usable
    // signing identity for that to work.
    repo.key_ensure_loaded()
        .expect("the fixture must provision an agent signing identity");
}

#[test]
fn fake_implementer_commits_a_change_and_writes_the_done_sentinel() {
    let fx = build_fixture();

    let status = Command::new("bash")
        .arg(fake_implementer())
        .current_dir(&fx.root)
        .status()
        .expect("spawn fake-implementer.sh");
    assert!(status.success(), "fake-implementer.sh should exit 0");

    // It edited the crate.
    let lib = std::fs::read_to_string(fx.root.join("src/lib.rs")).expect("read lib.rs");
    assert!(
        lib.contains("fn say_hi"),
        "the worker should have added say_hi to the crate"
    );

    // It wrote result.md and then the DONE sentinel (REQ-3b), which must parse
    // and list the result artifact.
    assert!(
        fx.root.join("_orchestrator/result.md").exists(),
        "the worker must emit result.md"
    );
    let done = std::fs::read_to_string(fx.root.join("_orchestrator/DONE")).expect("read DONE");
    let done: serde_json::Value = serde_json::from_str(&done).expect("DONE must be valid JSON");
    assert_eq!(done["exit_status"], "success");
    assert_eq!(
        done["artifacts"][0]["path"], "_orchestrator/result.md",
        "DONE must list the result artifact"
    );

    // The change is committed in jj (the Implementer owns the describe).
    let out = Command::new("jj")
        .args(["log", "--no-graph", "-T", "description"])
        .current_dir(&fx.root)
        .output()
        .expect("jj log");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("say_hi"),
        "the worker's change should be described in the jj log"
    );

    // The committed change must be EXACTLY the code — no crosslink scaffolding
    // (that lives in the `main` baseline) and no `_orchestrator/` scratch (it is
    // gitignored). Anything else here would land on `main` (REQ-3, REQ-17). An
    // exact-set check, not a `contains`, is what catches a scaffolding leak.
    let diff = Command::new("jj")
        .args(["diff", "--name-only"])
        .current_dir(&fx.root)
        .output()
        .expect("jj diff");
    let stdout = String::from_utf8_lossy(&diff.stdout);
    let mut changed: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    changed.sort_unstable();
    assert_eq!(
        changed,
        ["src/lib.rs"],
        "the worker change must be exactly the code, got {changed:?}"
    );
}
