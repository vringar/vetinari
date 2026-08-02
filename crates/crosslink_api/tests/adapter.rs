//! Integration test for the crosslink_api adapter: round-trips issue reads,
//! comments, and labels against a throwaway crosslink repository.
//!
//! The fixture repository is built with crosslink's own `db` API, so the test
//! exercises the adapter end to end without a `crosslink` subprocess.

use crosslink::db::Database;
use vetinari_crosslink_api::{CrosslinkError, CrosslinkRepo};

/// Build a `.crosslink/` repository under `root` with one issue, returning its
/// id.
fn fixture_repo(root: &std::path::Path) -> i64 {
    let crosslink_dir = root.join(".crosslink");
    std::fs::create_dir_all(&crosslink_dir).expect("create .crosslink dir");
    let db = Database::open(&crosslink_dir.join("issues.db")).expect("open database");
    db.create_issue("Adapter test issue", Some("a description"), "high")
        .expect("create issue")
}

#[test]
fn reads_an_issue_with_its_labels() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let id = fixture_repo(tmp.path());
    let repo = CrosslinkRepo::open(tmp.path()).expect("open crosslink repo");

    let issue = repo.read_issue(id).expect("read issue");
    assert_eq!(issue.id, id);
    assert_eq!(issue.title, "Adapter test issue");
    assert_eq!(issue.description.as_deref(), Some("a description"));
    assert_eq!(issue.status, "open");
    assert_eq!(issue.priority, "high");
    assert!(issue.labels.is_empty());
}

#[test]
fn adds_and_removes_labels() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let id = fixture_repo(tmp.path());
    let repo = CrosslinkRepo::open(tmp.path()).expect("open crosslink repo");

    assert!(repo.label_add(id, "area:foundation").expect("add label"));
    // Adding the same label again is idempotent.
    assert!(!repo.label_add(id, "area:foundation").expect("re-add label"));
    assert_eq!(
        repo.read_issue(id).expect("read issue").labels,
        vec!["area:foundation".to_string()]
    );

    assert!(repo
        .label_remove(id, "area:foundation")
        .expect("remove label"));
    assert!(!repo
        .label_remove(id, "area:foundation")
        .expect("re-remove label"));
    assert!(repo.read_issue(id).expect("read issue").labels.is_empty());
}

#[test]
fn writes_a_comment_and_rejects_an_unknown_kind() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let id = fixture_repo(tmp.path());
    let repo = CrosslinkRepo::open(tmp.path()).expect("open crosslink repo");

    let comment_id = repo
        .comment_write(id, "result", "the work is done", Some("implementer"))
        .expect("write comment");
    assert!(comment_id > 0, "a real comment id is returned");

    let err = repo
        .comment_write(id, "not-a-real-kind", "body", None)
        .expect_err("an unknown comment kind must be rejected");
    assert!(matches!(err, CrosslinkError::InvalidCommentKind { .. }));
}

#[test]
fn missing_issue_is_a_distinct_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    fixture_repo(tmp.path());
    let repo = CrosslinkRepo::open(tmp.path()).expect("open crosslink repo");

    let err = repo
        .read_issue(999_999)
        .expect_err("issue should not exist");
    assert!(matches!(err, CrosslinkError::IssueNotFound { id: 999_999 }));
}

#[test]
fn opening_a_non_crosslink_directory_fails() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let err = CrosslinkRepo::open(tmp.path()).expect_err("not a crosslink repo");
    assert!(matches!(err, CrosslinkError::NotARepository));
}

#[test]
fn list_by_label_returns_matching_open_issues_with_labels() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let crosslink_dir = tmp.path().join(".crosslink");
    std::fs::create_dir_all(&crosslink_dir).expect("mkdir .crosslink");
    let db = Database::open(&crosslink_dir.join("issues.db")).expect("open db");

    // Two graphed issues, one unlabeled, one graphed-but-closed.
    let a = db.create_issue("Graphed A", None, "high").expect("a");
    let b = db.create_issue("Graphed B", None, "low").expect("b");
    let c = db.create_issue("Unlabeled C", None, "low").expect("c");
    let d = db.create_issue("Closed graphed D", None, "low").expect("d");
    for id in [a, b, d] {
        db.add_label(id, "phase:graphed").expect("label");
    }
    db.add_label(a, "round:0").expect("extra label");
    db.add_label(c, "phase:merged").expect("label c");
    db.close_issue(d).expect("close d");

    let repo = CrosslinkRepo::open(tmp.path()).expect("open repo");
    let graphed = repo
        .list_by_label("open", "phase:graphed")
        .expect("list graphed");

    // Only the two OPEN graphed issues, in ascending id order.
    let ids: Vec<i64> = graphed.iter().map(|i| i.id).collect();
    assert_eq!(ids, vec![a, b], "closed and unlabeled issues excluded");
    // Each carries its full label set.
    let issue_a = graphed.iter().find(|i| i.id == a).unwrap();
    assert!(issue_a.labels.iter().any(|l| l == "phase:graphed"));
    assert!(issue_a.labels.iter().any(|l| l == "round:0"));
}

#[test]
fn open_blockers_reports_only_open_blocking_issues() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let crosslink_dir = tmp.path().join(".crosslink");
    std::fs::create_dir_all(&crosslink_dir).expect("mkdir .crosslink");
    let db = Database::open(&crosslink_dir.join("issues.db")).expect("open db");

    let target = db.create_issue("Blocked target", None, "high").expect("t");
    let open_blocker = db.create_issue("Open blocker", None, "low").expect("ob");
    let closed_blocker = db.create_issue("Closed blocker", None, "low").expect("cb");
    // add_dependency(target, blocker): both block `target`.
    db.add_dependency(target, open_blocker).expect("dep open");
    db.add_dependency(target, closed_blocker)
        .expect("dep closed");
    db.close_issue(closed_blocker).expect("close blocker");

    let repo = CrosslinkRepo::open(tmp.path()).expect("open repo");
    let open = repo.open_blockers(target).expect("open blockers");
    assert_eq!(
        open,
        vec![open_blocker],
        "only the still-open blocker gates the target"
    );

    // Once the last open blocker closes, the target is unblocked.
    db.close_issue(open_blocker).expect("close last blocker");
    assert!(
        repo.open_blockers(target).expect("recheck").is_empty(),
        "a fully-closed blocker set leaves no open blockers"
    );
}

#[test]
fn tracker_remote_reads_the_landing_mode_gate() {
    let tmp = tempfile::tempdir().expect("tempdir");
    fixture_repo(tmp.path());
    let crosslink_dir = tmp.path().join(".crosslink");
    let repo = CrosslinkRepo::open(tmp.path()).expect("open crosslink repo");

    // No config file at all ⇒ local mode (None).
    assert_eq!(repo.tracker_remote().expect("no config"), None);

    // An empty string in the team config is still local mode.
    std::fs::write(
        crosslink_dir.join("hook-config.json"),
        r#"{"tracker_remote": ""}"#,
    )
    .expect("write team config");
    assert_eq!(repo.tracker_remote().expect("empty team"), None);

    // A set value in the team config ⇒ remote mode.
    std::fs::write(
        crosslink_dir.join("hook-config.json"),
        r#"{"tracker_remote": "origin"}"#,
    )
    .expect("write team config");
    assert_eq!(
        repo.tracker_remote().expect("team set").as_deref(),
        Some("origin")
    );

    // The local override wins over the team config.
    std::fs::write(
        crosslink_dir.join("hook-config.local.json"),
        r#"{"tracker_remote": "upstream"}"#,
    )
    .expect("write local config");
    assert_eq!(
        repo.tracker_remote()
            .expect("local overrides team")
            .as_deref(),
        Some("upstream"),
        "local config must take precedence over team config"
    );
}

#[test]
fn signing_without_an_identity_reports_identity_unavailable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    fixture_repo(tmp.path());
    let repo = CrosslinkRepo::open(tmp.path()).expect("open crosslink repo");

    // The fixture repo has no agent.json, so no signing key is configured.
    let err = repo
        .key_ensure_loaded()
        .expect_err("no identity should be loadable");
    assert!(matches!(err, CrosslinkError::IdentityUnavailable { .. }));
}
