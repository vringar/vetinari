//! AC-11a — the fixture dogfood: drive one crosslink issue from `phase:graphed`
//! to `phase:merged`, HEADLESS, with the Direct fake worker (no live claude).
//!
//! This is the MVP definition-of-done. It stands up the `hello` fixture (a
//! self-contained jj + crosslink repo with one `phase:graphed` issue and the
//! fake-implementer worker), constructs the [`BuildPump`] against it, runs
//! [`BuildPump::run_until_idle`], and asserts the full graphed → merged loop:
//!
//! - the seed issue reaches [`Phase::Merged`] in `state.db`;
//! - `main` fast-forwarded to the worker's `say_hi` change (read through the
//!   `.jj/` gate);
//! - the fixture crate now carries `say_hi` on `main`;
//! - `events.jsonl` recorded the phase transitions.
//!
//! No Anthropic API, no live `claude`, deterministic. The only shell-outs are
//! test-support (`build_fixture` drives the `jj`/`crosslink` CLIs to provision
//! the repo, and the assertions read the jj log) — the orchestrator side runs
//! entirely through library calls (AC-24).

mod common;

use std::path::Path;
use std::process::Command;

use common::{build_fixture, fake_adversary_clean, fake_implementer, unique_session};
use orchestrator::config::{OrchestratorConfig, WorkerConfig};
use orchestrator::events::{read_all, EventLog, ORCHESTRATOR_DIR};
use orchestrator::pump::{BuildPump, IssueOutcome};
use orchestrator::spawn::Spawner;
use orchestrator::state::{EventKind, Phase, StateDb};
use orchestrator::workspace::WorkspaceManager;
use vetinari_crosslink_api::CrosslinkRepo;

/// The commit `main` points at in the repo at `cwd` (test-support read).
fn main_commit(cwd: &Path) -> String {
    let out = Command::new("jj")
        .args(["log", "-r", "main", "--no-graph", "-T", "commit_id"])
        .current_dir(cwd)
        .output()
        .expect("jj log for main");
    assert!(out.status.success(), "jj log must succeed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The `say_hi` presence in the crate as `main` sees it (test-support read).
fn main_has_say_hi(cwd: &Path) -> bool {
    let out = Command::new("jj")
        .args(["file", "show", "-r", "main", "src/lib.rs"])
        .current_dir(cwd)
        .output()
        .expect("jj file show main:src/lib.rs");
    assert!(out.status.success(), "jj file show must succeed");
    String::from_utf8_lossy(&out.stdout).contains("fn say_hi")
}

/// AC-11a: the whole loop, headless. graphed → implementing → qa-gate →
/// landing → merged, using the Direct fake worker.
#[test]
fn ac11a_dogfood_drives_graphed_to_merged_headless() {
    let fx = build_fixture();
    let orchestrator_dir = fx.root.join(ORCHESTRATOR_DIR);

    // Precondition: `main` does not yet carry the worker's change.
    let main_before = main_commit(&fx.root);
    assert!(
        !main_has_say_hi(&fx.root),
        "precondition: main must not yet contain say_hi"
    );

    // The pump's collaborators, all pointed at the fixture.
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("open state.db");
    let log = EventLog::open(&orchestrator_dir).expect("open events.jsonl");
    let manager = WorkspaceManager::load(&fx.root).expect("load workspace manager");
    let crosslink = CrosslinkRepo::open(&fx.root).expect("open crosslink repo");

    let (session, _guard) = unique_session("dogfood");
    // The Direct worker path skips the pin guard, so the pin value is unused.
    let spawner = Spawner::new(session, &fx.root, common::bwrap_pin());

    // Config: dispatch the committed fake implementer as the Direct worker. Its
    // absolute path passes through `worker_argv` untouched (the default relative
    // path would not resolve under the temp-dir fixture root).
    let config = OrchestratorConfig {
        worker: WorkerConfig {
            argv: vec![
                "bash".to_owned(),
                fake_implementer().to_string_lossy().into_owned(),
            ],
            // A2: the adversary review now runs between QA-pass and landing. Use
            // the Direct clean fake-adversary (empty, DONE-attested findings) so
            // the first review round converges → lands → merged, unchanged.
            adversary_argv: vec![
                "bash".to_owned(),
                fake_adversary_clean().to_string_lossy().into_owned(),
            ],
            ..WorkerConfig::default()
        },
        // A tight worker timeout keeps a hung fixture from stalling CI; the fake
        // worker is a sub-second bash script.
        worker_timeout_secs: 60,
        // Pin the dogfood to a single clean round so it lands on the first
        // adversary pass (the default n_rounds = 2 is exercised by the A3
        // convergence tests, not the dogfood).
        convergence: orchestrator::config::ConvergenceConfig {
            n_rounds: 1,
            ..Default::default()
        },
        ..OrchestratorConfig::default()
    };

    let pump = BuildPump::new(config, state, log, manager, spawner, crosslink);

    // Drive to idle — no issue left in a non-terminal phase.
    let outcomes = pump.run_until_idle().expect("pump must run to idle");

    // --- ASSERT: the seed issue merged --------------------------------------
    assert_eq!(
        outcomes,
        vec![(fx.issue_id, IssueOutcome::Merged)],
        "the single seed issue must land in one pass, got {outcomes:?}"
    );

    // Re-open the state.db to read the persisted authority (the pump owns its
    // handle for the loop; a fresh reader proves durability).
    let state = StateDb::open(orchestrator_dir.join("state.db")).expect("reopen state.db");
    let key = fx.issue_id.to_string();
    let issue = state
        .get_issue(&key)
        .expect("read issue")
        .expect("issue row exists");
    assert_eq!(
        issue.phase,
        Phase::Merged,
        "state.db must read phase:merged"
    );
    assert_eq!(issue.phase_substate, None, "merged clears the substate");

    // --- ASSERT: main fast-forwarded to the worker's say_hi change ----------
    let main_after = main_commit(&fx.root);
    assert_ne!(main_after, main_before, "main must have advanced");
    assert!(
        main_has_say_hi(&fx.root),
        "the fixture crate must now carry say_hi on main"
    );

    // --- ASSERT: crosslink reflects the terminal phase (presentation, REQ-2) --
    let info = crosslink_reopen(&fx.root)
        .read_issue(fx.issue_id)
        .expect("read issue");
    assert!(
        info.labels.iter().any(|l| l == "phase:merged"),
        "crosslink must mirror phase:merged, got {:?}",
        info.labels
    );
    assert!(
        !info.labels.iter().any(|l| l == "phase:graphed"),
        "the stale phase:graphed label must be removed, got {:?}",
        info.labels
    );

    // --- ASSERT: events.jsonl recorded the transitions ----------------------
    let events = read_all(orchestrator_dir.join("events.jsonl")).expect("read events");
    let transitions: Vec<(String, String)> = events
        .iter()
        .filter(|e| e.kind == EventKind::Transition)
        .filter_map(|e| {
            let from = e.payload.get("from_phase")?.as_str()?.to_owned();
            let to = e.payload.get("to_phase")?.as_str()?.to_owned();
            Some((from, to))
        })
        .collect();
    // The full happy-path chain must appear, in order.
    assert!(
        contains_subsequence(
            &transitions,
            &[
                ("graphed", "implementing"),
                ("implementing", "qa-gate"),
                ("landing", "merged"),
            ],
        ),
        "events.jsonl must record graphed→implementing→qa-gate→…→landing→merged, got {transitions:?}"
    );
    // A QA pass was recorded.
    assert!(
        events.iter().any(|e| e.kind == EventKind::QaResult
            && e.payload.get("result").and_then(|v| v.as_str()) == Some("pass")),
        "events.jsonl must record the QA pass"
    );
}

/// Re-open a fresh crosslink handle on the fixture (the pump consumed the
/// original when it was moved into it).
fn crosslink_reopen(root: &Path) -> CrosslinkRepo {
    CrosslinkRepo::open(root).expect("reopen crosslink repo")
}

/// Whether `needles` appears as an (not necessarily contiguous) ordered
/// subsequence of `haystack`.
fn contains_subsequence(haystack: &[(String, String)], needles: &[(&str, &str)]) -> bool {
    let mut it = haystack.iter();
    needles
        .iter()
        .all(|(nf, nt)| it.any(|(hf, ht)| hf == nf && ht == nt))
}
