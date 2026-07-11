//! Workspace-lifecycle integration test (REQ-5a, REQ-12).
//!
//! Exercises [`orchestrator::workspace::WorkspaceManager`] against a *real* jj
//! repository (the `hello` dogfood fixture stood up by [`common::build_fixture`],
//! which drives the `jj`/`crosslink` CLIs). Every workspace operation under test
//! goes through the library gate — no `jj`/`rm` subprocess.
//!
//! Covered:
//! - `prepare` when nothing exists → idempotent forget+rm succeeds, then create.
//! - `list` shows the created workspace.
//! - `prepare` again over an existing workspace → forget+rm+recreate cleanly.
//! - `forget` tears it down (workspace and directory both gone).

mod common;

use orchestrator::state::Phase;
use orchestrator::workspace::{WorkspaceManager, WorkspaceName};

/// The whole lifecycle in one test: a single fixture repo is expensive to stand
/// up (it shells out to `jj` + `crosslink`), so drive the sequence linearly.
#[test]
fn prepare_list_reprepare_forget() {
    let fixture = common::build_fixture();
    let manager = WorkspaceManager::load(&fixture.root).expect("load repo into gate");

    let name = WorkspaceName::generate(Phase::Implementing, "42", 3);
    let dir = manager.workspace_dir(&name);

    // 1. prepare when nothing exists: cleanup is a no-op forget + absent-dir rm,
    //    then a fresh create. The LANDMINE (forget errors on a missing
    //    workspace) must be swallowed here.
    let prepared = manager.prepare(&name, "main").expect("prepare fresh");
    assert_eq!(prepared.name(), &name);
    assert_eq!(prepared.path(), dir);
    assert!(dir.is_dir(), "prepared workspace directory must exist");
    assert!(
        dir.join(".jj").exists(),
        "the workspace must be registered with jj (`.jj` marker present)"
    );

    // 2. list shows it.
    let names = manager.list().expect("list workspaces");
    assert!(
        names.contains(&name.as_str()),
        "list {names:?} must contain {}",
        name.as_str()
    );

    // 3. Drop a sentinel file, then prepare again over the *existing* workspace.
    //    A clean recreate must forget the old registration and remove the old
    //    directory — so the sentinel is gone afterwards.
    let sentinel = dir.join("stale-marker.txt");
    std::fs::write(&sentinel, b"orphan from a prior attempt").expect("write sentinel");
    assert!(sentinel.exists());

    let reprepared = manager
        .prepare(&name, "main")
        .expect("re-prepare over existing");
    assert_eq!(reprepared.path(), dir);
    assert!(dir.is_dir(), "recreated workspace directory must exist");
    assert!(
        !sentinel.exists(),
        "re-prepare must rm -rf the old directory (stale sentinel survived)"
    );
    // The name is registered exactly once — recreate did not duplicate it.
    let names = manager.list().expect("list after re-prepare");
    assert_eq!(
        names.iter().filter(|n| **n == name.as_str()).count(),
        1,
        "re-prepared workspace must be registered exactly once, saw {names:?}"
    );

    // 4. forget: both the jj registration and the directory go away.
    manager.forget(&name).expect("forget");
    let names = manager.list().expect("list after forget");
    assert!(
        !names.contains(&name.as_str()),
        "forgotten workspace must be gone from {names:?}"
    );
    assert!(!dir.exists(), "forget must remove the directory");

    // 5. forget again is idempotent (no such workspace, absent dir) — must not
    //    error.
    manager.forget(&name).expect("second forget is a no-op");
}

/// Idempotent-cleanup / re-prepare must leave the repository observably
/// identical whether prepare runs once or twice — the practical statement of
/// REQ-12's "every time" guarantee. (The proptest suite proves this over
/// arbitrary names against a pure model; here we confirm it against real jj.)
///
/// Comparing names alone can't see the `.jj/` corruption REQ-5a guards — an
/// orphaned working-copy commit shows the same name. So this asserts on the
/// full [`WorkspaceEntry`] (name + `working_copy_id`) around the re-prepare:
/// - the target name is registered exactly once each time (no duplicate /
///   orphaned registration), and
/// - the second prepare re-mints a *fresh* empty working-copy commit — its id
///   must differ from the first (a no-op skip that reused the old commit would
///   fail this), while every *other* workspace's commit is untouched.
#[test]
fn re_prepare_is_observationally_idempotent() {
    let fixture = common::build_fixture();
    let manager = WorkspaceManager::load(&fixture.root).expect("load repo into gate");
    let name = WorkspaceName::generate(Phase::AdversaryReview, "L3", 0);
    let name_str = name.as_str();

    manager.prepare(&name, "main").expect("prepare once");
    let after_one = manager.entries().expect("entries after one prepare");
    let wc_one = entry_wc(&after_one, &name_str);

    manager.prepare(&name, "main").expect("prepare twice");
    let after_two = manager.entries().expect("entries after two prepares");
    let wc_two = entry_wc(&after_two, &name_str);

    // Registered exactly once each time — no duplicated / orphaned registration.
    assert_eq!(
        after_one.iter().filter(|e| e.name == name_str).count(),
        1,
        "one prepare must register the name exactly once, saw {after_one:?}"
    );
    assert_eq!(
        after_two.iter().filter(|e| e.name == name_str).count(),
        1,
        "re-prepare must register the name exactly once, saw {after_two:?}"
    );

    // The set of registered names is unchanged by the second prepare.
    let names_one: Vec<&str> = after_one.iter().map(|e| e.name.as_str()).collect();
    let names_two: Vec<&str> = after_two.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names_one, names_two,
        "re-prepare must not add or drop any workspace"
    );

    // The re-prepared workspace got a genuinely fresh working-copy commit; a
    // no-op skip that left the first attempt's commit in place would match here.
    assert_ne!(
        wc_one, wc_two,
        "re-prepare must mint a fresh empty working-copy commit, not reuse the old one"
    );

    // Every *other* workspace's working copy is untouched by the re-prepare.
    for e in &after_one {
        if e.name == name_str {
            continue;
        }
        let other = after_two
            .iter()
            .find(|o| o.name == e.name)
            .unwrap_or_else(|| panic!("workspace `{}` vanished across re-prepare", e.name));
        assert_eq!(
            e.working_copy_id, other.working_copy_id,
            "re-prepare must not disturb unrelated workspace `{}`",
            e.name
        );
    }
}

/// The `working_copy_id` of the entry named `name`, asserting it is present.
fn entry_wc<'a>(entries: &'a [vetinari_jj_api::WorkspaceEntry], name: &str) -> &'a str {
    entries
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.working_copy_id.as_str())
        .unwrap_or_else(|| panic!("workspace `{name}` not registered, saw {entries:?}"))
}
