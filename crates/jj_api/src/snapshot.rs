//! The working-copy `snapshot` operation: fold a workspace's on-disk edits into
//! its recorded working-copy commit, exactly as the `jj` CLI does at the start
//! of every command.
//!
//! The read-only operations ([`crate::status`], the `resolve` reads) observe the
//! *recorded* working-copy commit and never snapshot first — correct when a
//! worker drove the `jj` CLI (which snapshots on every invocation). But the
//! orchestrator must not *trust* a worker to have run a snapshotting verb before
//! it reads the result back: a Merger that resolves a conflict purely through
//! file edits (the `Edit` tool, never a `jj` command) leaves its working-copy
//! commit stale, so a naive readback still reports the old conflicted tree. This
//! operation forces the snapshot so the recorded commit reflects on-disk reality
//! before the orchestrator reads its conflict state (REQ-19, F5).

use jj_lib::gitignore::GitIgnoreFile;
use jj_lib::matchers::NothingMatcher;
use jj_lib::repo::Repo;
use jj_lib::working_copy::SnapshotOptions;

use crate::error::{JjError, Result};
use crate::workspace::JjWorkspace;

impl JjWorkspace {
    /// Snapshot this workspace's working copy: fold any on-disk edits to
    /// already-tracked files into the working-copy commit and persist the
    /// result, mirroring what the `jj` CLI does at the start of every command.
    ///
    /// Already-tracked files are always snapshotted; **no new files are tracked**
    /// (a [`NothingMatcher`] start-tracking matcher), so this only refreshes the
    /// recorded tree from the tracked working-copy files — it never begins
    /// tracking stray artifacts a worker left behind. A no-op (no new operation)
    /// when the on-disk tree already matches the recorded commit, so it is safe
    /// to call unconditionally before reading a workspace's conflict state.
    pub fn snapshot_working_copy(&mut self) -> Result<()> {
        let repo = self.repo_at_head()?;
        let workspace_name = self.workspace.workspace_name().to_owned();
        let wc_commit_id = repo
            .view()
            .get_wc_commit_id(&workspace_name)
            .ok_or_else(|| JjError::Snapshot {
                source: "workspace has no working-copy commit in the current view".into(),
            })?
            .clone();
        let wc_commit =
            repo.store()
                .get_commit(&wc_commit_id)
                .map_err(|source| JjError::Snapshot {
                    source: Box::new(source),
                })?;

        // Snapshot only what is already tracked: refresh the recorded tree, never
        // begin tracking new files, and never reject a large already-tracked file
        // (already-tracked files are always snapshotted regardless of size).
        let options = SnapshotOptions {
            base_ignores: GitIgnoreFile::empty(),
            progress: None,
            start_tracking_matcher: &NothingMatcher,
            force_tracking_matcher: &NothingMatcher,
            max_new_file_size: u64::MAX,
        };

        pollster::block_on(async {
            let mut locked_ws =
                self.workspace
                    .start_working_copy_mutation()
                    .await
                    .map_err(|source| JjError::Snapshot {
                        source: Box::new(source),
                    })?;
            let (new_tree, _stats) =
                locked_ws
                    .locked_wc()
                    .snapshot(&options)
                    .await
                    .map_err(|source| JjError::Snapshot {
                        source: Box::new(source),
                    })?;

            if new_tree.tree_ids_and_labels() != wc_commit.tree().tree_ids_and_labels() {
                // On-disk edits diverge from the recorded commit: rewrite the
                // working-copy commit onto the snapshotted tree, re-point the
                // workspace at it, and rebase any descendants — the same sequence
                // the `jj` CLI performs when it auto-snapshots.
                let mut tx = repo.start_transaction();
                tx.set_is_snapshot(true);
                let mut_repo = tx.repo_mut();
                let commit = mut_repo
                    .rewrite_commit(&wc_commit)
                    .set_tree(new_tree)
                    .write()
                    .await
                    .map_err(|source| JjError::Snapshot {
                        source: Box::new(source),
                    })?;
                mut_repo
                    .set_wc_commit(workspace_name, commit.id().clone())
                    .map_err(|source| JjError::Snapshot {
                        source: Box::new(source),
                    })?;
                mut_repo
                    .rebase_descendants()
                    .await
                    .map_err(|source| JjError::Snapshot {
                        source: Box::new(source),
                    })?;
                let repo = tx.commit("snapshot working copy").await.map_err(|source| {
                    JjError::Snapshot {
                        source: Box::new(source),
                    }
                })?;
                locked_ws
                    .finish(repo.op_id().clone())
                    .await
                    .map_err(|source| JjError::Snapshot {
                        source: Box::new(source),
                    })?;
            } else {
                // No divergence: release the working-copy lock at the current
                // operation without writing a new (empty) snapshot operation.
                locked_ws
                    .finish(repo.op_id().clone())
                    .await
                    .map_err(|source| JjError::Snapshot {
                        source: Box::new(source),
                    })?;
            }
            Ok::<_, JjError>(())
        })
    }
}
