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
