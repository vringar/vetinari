//! AC-2: `.orchestrator/state.db` is created on first run and its in-flight
//! state survives an orchestrator restart.
//!
//! The test simulates a crash by dropping the [`StateDb`] handle (closing the
//! SQLite connection) and reopening the same file, then asserts every table's
//! rows are reconstructed unchanged. **(REQ-2, REQ-3b, REQ-15)**

use std::path::PathBuf;

use orchestrator::state::{
    ActiveWorkerRow, EventKind, IssueRow, Phase, PhaseSubstate, PostedArtifact, StateDb, WorkerRole,
};

#[test]
fn state_db_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join(".orchestrator/state.db");

    // --- in-flight state to persist across the simulated restart ---
    let issue = {
        let mut i = IssueRow::new("#42", Phase::Landing);
        i.round = 3;
        i.empty_round_streak = 2;
        i.last_diff_hash = Some("deadbeef".into());
        i.landing_retry_count = 1;
        i.phase_substate = Some(
            PhaseSubstate::RebaseDoneBookmarkPending
                .as_str()
                .to_string(),
        );
        i
    };
    let worker = ActiveWorkerRow {
        worker_uuid: "worker-uuid-7".into(),
        issue_id: "#42".into(),
        role: WorkerRole::Implementer,
        round: 3,
        workspace_path: PathBuf::from("/tmp/.workspace/implement-42-r3"),
        pid: Some(2718),
        spawned_at: 1_700_000_000,
        last_heartbeat: 1_700_000_050,
    };
    let posted = PostedArtifact {
        worker_uuid: "worker-uuid-7".into(),
        artifact_path: "_orchestrator/findings.jsonl".into(),
        content_sha: "sha-1".into(),
        finding_index: 0,
        comment_id: "comment-99".into(),
        posted_at: 1_700_000_060,
    };

    // --- first run: the binary creates state.db and writes its state ---
    {
        let db = StateDb::open(&db_path).expect("first open creates state.db");
        assert!(
            db_path.exists(),
            "AC-2: state.db is created on first run via the in-binary migration"
        );
        db.upsert_issue(&issue).unwrap();
        db.upsert_worker(&worker).unwrap();
        assert!(db.record_posted(&posted).unwrap());
        db.append_event(
            EventKind::Transition,
            Some("#42"),
            Some("worker-uuid-7"),
            &serde_json::json!({"from": "implementing", "to": "landing"}),
        )
        .unwrap();
        // `db` dropped here — closes the connection, as if the orchestrator
        // process were killed mid-tick.
    }

    // --- restart: reopen the same file, expect the state reconstructed ---
    let db = StateDb::open(&db_path).expect("reopen after restart");

    assert_eq!(
        db.get_issue("#42").unwrap(),
        Some(issue),
        "the issue row, including its in-flight phase_substate, must round-trip"
    );
    assert_eq!(
        db.get_worker("worker-uuid-7").unwrap(),
        Some(worker),
        "the active worker row must round-trip"
    );
    // REQ-3b: the posted-artifacts ledger persists, so re-translating the same
    // artifact after a crash mid-translation is a no-op.
    assert!(
        !db.record_posted(&posted).unwrap(),
        "the posted_artifacts row must survive the restart"
    );

    let events = db.recent_events(10).unwrap();
    assert_eq!(
        events.len(),
        1,
        "the appended event must survive the restart"
    );
    assert_eq!(events[0].kind, EventKind::Transition);
    assert_eq!(events[0].issue_id.as_deref(), Some("#42"));
    assert_eq!(events[0].payload["to"], "landing");
}
