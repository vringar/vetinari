//! AC-25: the `jj_api` workspace lifecycle runs entirely through library
//! calls — no `jj` subprocess is spawned.
//!
//! This test drives `add → status → diff → describe → list` (plus `log`,
//! bookmarks, and `rebase`) against a throwaway repository. Every call goes
//! through `jj-lib` or the adapter; nothing here spawns a process. The
//! complementary guarantees are the AC-24 "no shell-out" lint (which fails the
//! build on any `Command::new("jj")`) and, in CI, an `strace` run over this
//! test asserting no `execve` of a `jj` binary.

use std::path::Path;

use jj_lib::backend::{CopyId, TreeValue};
use jj_lib::config::{ConfigLayer, ConfigSource, StackedConfig};
use jj_lib::merge::Merge;
use jj_lib::merged_tree_builder::MergedTreeBuilder;
use jj_lib::ref_name::WorkspaceName;
use jj_lib::repo::Repo;
use jj_lib::repo_path::{RepoPath, RepoPathBuf};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::Workspace;
use vetinari_jj_api::{ChangeKind, JjWorkspace};

/// Minimal settings: jj-lib defaults plus an identity (jj never defaults one).
fn test_settings() -> UserSettings {
    let mut config = StackedConfig::with_defaults();
    let layer = ConfigLayer::parse(
        ConfigSource::Repo,
        "user.name = 'ac25-test'\nuser.email = 'ac25@vetinari.invalid'\n",
    )
    .expect("identity config parses");
    config.add_layer(layer);
    UserSettings::from_config(config).expect("settings build from config")
}

/// Initialize a repository at `repo_root` whose default workspace's
/// working-copy commit adds a single file, `hello.txt`. Built entirely with
/// `jj-lib`, so the fixture itself spawns no subprocess either.
fn init_repo_with_file(repo_root: &Path) {
    let settings = test_settings();
    let (_workspace, repo) = pollster::block_on(Workspace::init_internal_git(&settings, repo_root))
        .expect("initialize repository");

    pollster::block_on(async {
        // Write the file's content as a blob. A `&[u8]` is itself an
        // `AsyncRead`, so it doubles as the content reader.
        let mut content: &[u8] = b"line one\nline two\n";
        let file_id = repo
            .store()
            .write_file(
                RepoPath::from_internal_string("hello.txt").expect("valid repo path"),
                &mut content,
            )
            .await
            .expect("write file blob");

        // Build a tree containing it on top of the empty root tree.
        let root_commit = repo.store().root_commit();
        let mut builder = MergedTreeBuilder::new(root_commit.tree());
        builder.set_or_remove(
            RepoPathBuf::from_internal_string("hello.txt").expect("valid repo path"),
            Merge::normal(TreeValue::File {
                id: file_id,
                executable: false,
                copy_id: CopyId::placeholder(),
            }),
        );
        let tree = builder.write_tree().await.expect("write tree");

        // Commit it and make it the default workspace's working-copy commit.
        let mut tx = repo.start_transaction();
        let commit = tx
            .repo_mut()
            .new_commit(vec![root_commit.id().clone()], tree)
            .set_description("add hello.txt")
            .write()
            .await
            .expect("write commit");
        tx.repo_mut()
            .set_wc_commit(WorkspaceName::DEFAULT.to_owned(), commit.id().clone())
            .expect("set working-copy commit");
        tx.commit("test setup")
            .await
            .expect("commit setup transaction");
    });
}

#[test]
fn workspace_lifecycle_through_library_calls() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let repo_root = tmp.path().join("repo");
    std::fs::create_dir(&repo_root).expect("create repo dir");
    init_repo_with_file(&repo_root);

    let ws = JjWorkspace::load(&repo_root).expect("load workspace");

    // log: one commit, the fixture's.
    let log = ws.log("@").expect("log @");
    assert_eq!(log.len(), 1, "expected exactly the fixture commit");
    assert_eq!(log[0].description, "add hello.txt");
    assert!(!log[0].has_conflict);

    // status: the working-copy commit adds hello.txt over the empty root.
    let status = ws.status().expect("status");
    assert_eq!(status.working_copy_id, log[0].commit_id);
    assert_eq!(status.changes.len(), 1);
    assert_eq!(status.changes[0].path, "hello.txt");
    assert_eq!(status.changes[0].kind, ChangeKind::Added);

    // diff: a git-format patch introducing hello.txt.
    let patch = ws.diff("root()", "@").expect("diff");
    assert!(
        patch.contains("diff --git a/hello.txt b/hello.txt"),
        "patch missing file header:\n{patch}"
    );
    assert!(
        patch.contains("new file mode 100644"),
        "patch missing new-file line:\n{patch}"
    );
    assert!(
        patch.contains("+line one"),
        "patch missing added content:\n{patch}"
    );

    // describe: rewrites the commit, preserving its change id.
    let described = ws
        .describe("@", "AC-25 lifecycle commit")
        .expect("describe @");
    assert_eq!(described.description, "AC-25 lifecycle commit");
    assert_eq!(described.change_id, log[0].change_id, "change id preserved");
    assert_ne!(described.commit_id, log[0].commit_id, "commit id rewritten");

    // bookmarks: create, list, reject duplicate, move.
    ws.bookmark_create("feature", "@").expect("bookmark_create");
    let bookmarks = ws.bookmark_list().expect("bookmark_list");
    assert_eq!(bookmarks.len(), 1);
    assert_eq!(bookmarks[0].name, "feature");
    assert_eq!(
        bookmarks[0].target.as_deref(),
        Some(described.commit_id.as_str())
    );
    assert!(
        ws.bookmark_create("feature", "@").is_err(),
        "creating a duplicate bookmark must fail"
    );
    ws.bookmark_move("feature", "root()")
        .expect("bookmark_move");

    // rebase: @ is already a child of root; rebasing it onto root() again
    // exercises the operation and must apply cleanly.
    let rebased = ws.rebase("@", "root()").expect("rebase @ onto root");
    assert!(!rebased.has_conflict);

    // workspace add → list: a second workspace, with the base content on disk.
    let w2_root = tmp.path().join("w2");
    ws.workspace_add(&w2_root, "w2", "@")
        .expect("workspace_add");
    let names = workspace_names(&ws);
    assert!(names.contains(&"default".to_string()));
    assert!(names.contains(&"w2".to_string()));
    assert!(
        w2_root.join("hello.txt").is_file(),
        "new workspace should have the base tree checked out"
    );

    // workspace forget: w2 is dropped from the repository.
    ws.workspace_forget("w2").expect("workspace_forget");
    assert!(!workspace_names(&ws).contains(&"w2".to_string()));
}

/// Names of every workspace currently in the repository.
fn workspace_names(ws: &JjWorkspace) -> Vec<String> {
    ws.workspace_list()
        .expect("workspace_list")
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}
