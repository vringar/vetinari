//! The `status` operation: what the current workspace's working-copy commit
//! changes relative to its parent.
//!
//! This is **read-only**. It reports the *recorded* working-copy commit and
//! does not snapshot the on-disk files first. In the orchestrator that is
//! exactly what's wanted: workers drive the `jj` CLI, which snapshots on every
//! invocation, so by the time the orchestrator inspects a workspace its
//! working-copy commit already reflects the worker's edits — and a read-only
//! `status` cannot corrupt that workspace.

use futures::StreamExt;
use jj_lib::matchers::EverythingMatcher;
use jj_lib::merged_tree::MergedTree;
use jj_lib::object_id::ObjectId;
use jj_lib::repo::Repo;

use crate::error::{JjError, Result};
use crate::workspace::JjWorkspace;

/// How a single path changed between two trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// The path exists in the new tree but not the old one.
    Added,
    /// The path exists in both trees with different content.
    Modified,
    /// The path existed in the old tree but not the new one.
    Removed,
}

/// One changed path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    /// Repository-relative path, always forward-slash separated.
    pub path: String,
    /// What kind of change this is.
    pub kind: ChangeKind,
}

/// Result of [`JjWorkspace::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceStatus {
    /// Full id of the workspace's working-copy commit.
    pub working_copy_id: String,
    /// Full ids of that commit's parents.
    pub parent_ids: Vec<String>,
    /// Paths the working-copy commit changes relative to its parent tree.
    pub changes: Vec<FileChange>,
}

impl JjWorkspace {
    /// Report what this workspace's working-copy commit changes relative to its
    /// parent.
    ///
    /// See the module docs: this does not snapshot the working copy.
    pub fn status(&self) -> Result<WorkspaceStatus> {
        let repo = self.repo_at_head()?;
        let wc_id = repo
            .view()
            .get_wc_commit_id(self.workspace.workspace_name())
            .ok_or_else(|| JjError::Backend {
                source: "workspace has no working-copy commit in the current view".into(),
            })?;
        let commit = repo
            .store()
            .get_commit(wc_id)
            .map_err(|source| JjError::Backend {
                source: Box::new(source),
            })?;
        let parent_tree =
            pollster::block_on(commit.parent_tree(repo.as_ref())).map_err(|source| {
                JjError::Backend {
                    source: Box::new(source),
                }
            })?;
        let changes = collect_tree_changes(&parent_tree, &commit.tree())?;
        Ok(WorkspaceStatus {
            working_copy_id: commit.id().hex(),
            parent_ids: commit.parent_ids().iter().map(ObjectId::hex).collect(),
            changes,
        })
    }
}

/// Diff two trees into a flat list of [`FileChange`]s. Shared by any operation
/// that needs the *set* of changed paths (as opposed to patch text).
pub(crate) fn collect_tree_changes(
    before: &MergedTree,
    after: &MergedTree,
) -> Result<Vec<FileChange>> {
    let matcher = EverythingMatcher;
    let entries = pollster::block_on(before.diff_stream(after, &matcher).collect::<Vec<_>>());
    let mut changes = Vec::with_capacity(entries.len());
    for entry in entries {
        let diff = entry.values.map_err(|source| JjError::Backend {
            source: Box::new(source),
        })?;
        let kind = match (diff.before.is_present(), diff.after.is_present()) {
            (false, true) => ChangeKind::Added,
            (true, false) => ChangeKind::Removed,
            // Present-on-both is a content change; absent-on-both never occurs
            // in a diff entry, so treat it as a (degenerate) modification.
            (true, true) | (false, false) => ChangeKind::Modified,
        };
        changes.push(FileChange {
            path: entry.path.as_internal_file_string().to_owned(),
            kind,
        });
    }
    Ok(changes)
}
