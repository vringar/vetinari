//! Integration tests for the read-only `vetinari` query CLI
//! (`.design/swarm-kickoff-spec.md` §2.2).
//!
//! Each test seeds a throwaway node — a `.orchestrator/state.db` built through
//! [`StateDb`], and (for the DAG-aware views) a `.crosslink/` repository built
//! directly through crosslink's `db` API, mirroring `crosslink_api`'s own
//! adapter test — then runs the compiled `vetinari` binary
//! (`CARGO_BIN_EXE_vetinari`) against it and asserts the rendered output. The
//! binary is exercised end to end, including its read-only second connection to
//! `state.db` while the test process still holds the writer open (the deployed
//! shape: the pump is the writer, the CLI is a concurrent reader).
//!
//! Running the real binary as a subprocess is the honest test of a read-only
//! introspection tool: it proves the actual `state.db` read path, arg parsing,
//! and rendering, and that the process never needs write access.

use std::path::Path;
use std::process::Command;

use crosslink::db::Database;
use orchestrator::state::{
    ActiveWorkerRow, EventKind, IssueRow, Phase, PhaseSubstate, StateDb, WorkerRole,
};

/// Run the `vetinari` binary against the node rooted at `root` (which contains
/// `.orchestrator/` and optionally `.crosslink/`) with `args`, returning its
/// stdout. Asserts a success exit.
fn run_vetinari(root: &Path, args: &[&str]) -> String {
    let bin = env!("CARGO_BIN_EXE_vetinari");
    let orchestrator_dir = root.join(".orchestrator");
    let mut full = vec![
        "--orchestrator-dir".to_string(),
        orchestrator_dir.to_str().unwrap().to_string(),
    ];
    full.extend(args.iter().map(|s| s.to_string()));
    let out = Command::new(bin)
        .args(&full)
        .output()
        .expect("spawn vetinari");
    assert!(
        out.status.success(),
        "vetinari {args:?} exited non-zero: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

/// Create `<root>/.orchestrator/state.db` and return an OPEN writer handle
/// (kept alive by the caller to model the running pump holding the WAL writer).
fn seed_state(root: &Path) -> StateDb {
    StateDb::open(root.join(".orchestrator").join("state.db")).expect("open state.db")
}

#[test]
fn status_lists_seeded_issues_as_a_table() {
    let tmp = tempfile::tempdir().unwrap();
    let db = seed_state(tmp.path());
    db.upsert_issue(&IssueRow::new("7", Phase::Implementing))
        .unwrap();
    let mut converged = IssueRow::new("9", Phase::Converged);
    converged.round = 2;
    converged.empty_round_streak = 2;
    db.upsert_issue(&converged).unwrap();

    let out = run_vetinari(tmp.path(), &["status"]);
    assert!(out.contains("#7"), "issue 7 shown: {out}");
    assert!(out.contains("implementing"), "phase shown: {out}");
    assert!(out.contains("#9") && out.contains("converged"), "{out}");
    assert!(out.contains("ROUND"), "header shown: {out}");
}

#[test]
fn status_single_issue_and_missing_issue() {
    let tmp = tempfile::tempdir().unwrap();
    let db = seed_state(tmp.path());
    let mut row = IssueRow::new("42", Phase::Landing);
    row.phase_substate = Some(PhaseSubstate::RebaseStarted.as_str().to_string());
    db.upsert_issue(&row).unwrap();

    let out = run_vetinari(tmp.path(), &["status", "--issue", "42"]);
    assert!(out.contains("#42") && out.contains("landing"), "{out}");
    assert!(out.contains("rebase_started"), "substate shown: {out}");

    // An id with no state.db row degrades to a clear message, not an error.
    let out = run_vetinari(tmp.path(), &["status", "--issue", "999"]);
    assert!(out.contains("not tracked"), "{out}");
}

#[test]
fn status_json_shape_is_asserted() {
    let tmp = tempfile::tempdir().unwrap();
    let db = seed_state(tmp.path());
    let mut row = IssueRow::new("7", Phase::QaGate);
    row.round = 1;
    row.landing_retry_count = 2;
    db.upsert_issue(&row).unwrap();

    let out = run_vetinari(tmp.path(), &["status", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    let arr = v.as_array().expect("top-level array");
    assert_eq!(arr.len(), 1);
    let obj = &arr[0];
    assert_eq!(obj["issue_id"], "7");
    assert_eq!(obj["phase"], "qa-gate");
    assert_eq!(obj["round"], 1);
    assert_eq!(obj["landing_retry_count"], 2);
    assert_eq!(obj["convergence_mode"], "n-rounds");
    // Nullable columns are present as JSON null, not absent.
    assert!(obj.get("phase_substate").is_some());
    assert!(obj.get("last_diff_hash").is_some());
}

#[test]
fn workers_lists_active_workers_with_heartbeat() {
    let tmp = tempfile::tempdir().unwrap();
    let db = seed_state(tmp.path());
    db.upsert_issue(&IssueRow::new("7", Phase::Implementing))
        .unwrap();
    let worker = ActiveWorkerRow {
        worker_uuid: "abcdef0123456789".into(),
        issue_id: "7".into(),
        role: WorkerRole::Implementer,
        round: 0,
        workspace_path: "/tmp/.workspace/implement-7".into(),
        pid: Some(4321),
        spawned_at: 100,
        last_heartbeat: 100,
    };
    db.upsert_worker(&worker).unwrap();

    let out = run_vetinari(tmp.path(), &["workers"]);
    assert!(out.contains("abcdef01"), "short uuid shown: {out}");
    assert!(out.contains("implementer"), "role shown: {out}");
    assert!(out.contains("4321"), "pid shown: {out}");
    // last_heartbeat is far in the past → flagged stale.
    assert!(out.contains("STALE"), "stale flag shown: {out}");

    let json = run_vetinari(tmp.path(), &["workers", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v[0]["role"], "implementer");
    assert_eq!(v[0]["stale"], true);
    assert!(v[0]["heartbeat_age_secs"].as_i64().unwrap() > 0);
}

#[test]
fn events_tail_shows_recent_events_oldest_first() {
    let tmp = tempfile::tempdir().unwrap();
    let db = seed_state(tmp.path());
    db.upsert_issue(&IssueRow::new("7", Phase::Implementing))
        .unwrap();
    for i in 0..5 {
        db.append_event(
            EventKind::Transition,
            Some("7"),
            None,
            &serde_json::json!({"n": i}),
        )
        .unwrap();
    }
    // Unrelated issue's event — must be filtered out by --issue.
    db.upsert_issue(&IssueRow::new("8", Phase::Graphed))
        .unwrap();
    db.append_event(
        EventKind::Spawn,
        Some("8"),
        None,
        &serde_json::json!({"n": 99}),
    )
    .unwrap();

    let out = run_vetinari(tmp.path(), &["events", "--tail", "2"]);
    // Only the two most recent events, chronological. The most recent overall
    // is the issue-8 spawn.
    assert!(out.contains("spawn"), "recent spawn shown: {out}");
    assert!(out.contains("KIND"), "header shown: {out}");

    let filtered = run_vetinari(tmp.path(), &["events", "--issue", "7", "--tail", "2"]);
    assert!(filtered.contains("#7"), "{filtered}");
    assert!(
        !filtered.contains("#8"),
        "issue filter excludes #8: {filtered}"
    );
    // The trailing two of issue 7's five events are n=3 and n=4.
    assert!(
        filtered.contains("\"n\":3") && filtered.contains("\"n\":4"),
        "{filtered}"
    );
}

#[test]
fn graph_joins_open_blockers_with_state_db_phase() {
    let tmp = tempfile::tempdir().unwrap();
    // crosslink repo: target #1 blocked by open #2 and closed #3.
    let crosslink_dir = tmp.path().join(".crosslink");
    std::fs::create_dir_all(&crosslink_dir).unwrap();
    let (target, open_blocker, closed_blocker) = {
        let cdb = Database::open(&crosslink_dir.join("issues.db")).unwrap();
        let target = cdb.create_issue("Target", None, "high").unwrap();
        let open_blocker = cdb.create_issue("Open blocker", None, "low").unwrap();
        let closed_blocker = cdb.create_issue("Closed blocker", None, "low").unwrap();
        cdb.add_dependency(target, open_blocker).unwrap();
        cdb.add_dependency(target, closed_blocker).unwrap();
        cdb.close_issue(closed_blocker).unwrap();
        cdb.add_label(target, "phase:graphed").unwrap();
        (target, open_blocker, closed_blocker)
    };

    // state.db: the target is Implementing, the open blocker Graphed.
    let db = seed_state(tmp.path());
    db.upsert_issue(&IssueRow::new(target.to_string(), Phase::Implementing))
        .unwrap();
    db.upsert_issue(&IssueRow::new(open_blocker.to_string(), Phase::Graphed))
        .unwrap();

    let out = run_vetinari(tmp.path(), &["graph"]);
    // The target row shows its execution phase and its ONE open blocker with
    // that blocker's phase (the closed blocker no longer gates).
    assert!(out.contains(&format!("#{target}")), "{out}");
    assert!(out.contains("implementing"), "target phase shown: {out}");
    assert!(
        out.contains(&format!("#{open_blocker}(graphed)")),
        "open blocker + its phase shown: {out}"
    );
    assert!(
        !out.contains(&format!("#{closed_blocker}(")),
        "closed blocker must not appear as a gate: {out}"
    );

    // JSON shape: target is not ready, open_blockers has exactly one entry.
    let json = run_vetinari(tmp.path(), &["graph", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let target_node = v
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["issue"] == target)
        .expect("target node present");
    assert_eq!(target_node["ready"], false);
    assert_eq!(target_node["open_blockers"].as_array().unwrap().len(), 1);
    assert_eq!(target_node["open_blockers"][0]["id"], open_blocker);
    assert_eq!(target_node["open_blockers"][0]["phase"], "graphed");
}

#[test]
fn crossbridge_shows_inbound_labels_with_not_active_note() {
    let tmp = tempfile::tempdir().unwrap();
    let crosslink_dir = tmp.path().join(".crosslink");
    std::fs::create_dir_all(&crosslink_dir).unwrap();
    let inbound = {
        let cdb = Database::open(&crosslink_dir.join("issues.db")).unwrap();
        let inbound = cdb.create_issue("Inbound request", None, "medium").unwrap();
        cdb.add_label(inbound, "xb:inbound").unwrap();
        cdb.add_label(inbound, "xb-source:peer-node-b").unwrap();
        cdb.add_label(inbound, "xb-status:pending").unwrap();
        inbound
    };
    // A state.db is present but need not track the inbound issue.
    let _db = seed_state(tmp.path());

    let out = run_vetinari(tmp.path(), &["crossbridge"]);
    assert!(
        out.contains("not yet active"),
        "clear integration-not-active note: {out}"
    );
    assert!(out.contains(&format!("#{inbound}")), "{out}");
    assert!(out.contains("peer-node-b"), "peer slug shown: {out}");
    assert!(out.contains("pending"), "xb-status shown: {out}");

    let json = run_vetinari(tmp.path(), &["crossbridge", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["integration_active"], false);
    assert_eq!(v["inbound"][0]["peer_slug"], "peer-node-b");
    assert_eq!(v["inbound"][0]["xb_status"], "pending");
}
