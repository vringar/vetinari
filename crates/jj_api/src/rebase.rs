//! The `rebase` operation: move a commit onto a new parent.

use jj_lib::object_id::ObjectId;
use jj_lib::rewrite::rebase_commit;

use crate::error::{JjError, Result};
use crate::log::CommitInfo;
use crate::workspace::JjWorkspace;

impl JjWorkspace {
    /// Rebase the commit `source` resolves to so its sole parent becomes the
    /// commit `destination` resolves to, then rebase its descendants onto the
    /// result. Returns metadata for the rebased commit.
    ///
    /// Both revsets must resolve to exactly one commit. The change id is
    /// preserved across the rebase.
    ///
    /// A rebase that cannot apply cleanly does **not** error: jj records the
    /// conflict in the rebased commit's tree and the operation succeeds. Check
    /// [`CommitInfo::has_conflict`] on the result to detect that case.
    pub fn rebase(&self, source: &str, destination: &str) -> Result<CommitInfo> {
        let repo = self.repo_at_head()?;
        let source_commit = self.resolve_single(repo.as_ref(), source)?;
        let destination_commit = self.resolve_single(repo.as_ref(), destination)?;
        let op_description = format!(
            "rebase commit {} onto {}",
            source_commit.id().hex(),
            destination_commit.id().hex()
        );
        let new_parents = vec![destination_commit.id().clone()];

        let mut tx = repo.start_transaction();
        let rebased = pollster::block_on(async {
            let rebased = {
                let mut_repo = tx.repo_mut();
                let rebased = rebase_commit(mut_repo, source_commit, new_parents)
                    .await
                    .map_err(|source| JjError::Backend {
                        source: Box::new(source),
                    })?;
                mut_repo
                    .rebase_descendants()
                    .await
                    .map_err(|source| JjError::Backend {
                        source: Box::new(source),
                    })?;
                rebased
            };
            tx.commit(op_description)
                .await
                .map_err(|source| JjError::Transaction {
                    operation: "rebase".to_owned(),
                    source: Box::new(source),
                })?;
            Ok::<_, JjError>(rebased)
        })?;

        Ok(CommitInfo::from_commit(&rebased))
    }
}
