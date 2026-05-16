//! The `describe` operation: set a commit's description.
//!
//! This is the adapter's first mutating operation. The shape — start a
//! transaction, rewrite the commit, rebase descendants onto the rewrite, then
//! commit the transaction — recurs in `rebase` and the bookmark operations.

use jj_lib::object_id::ObjectId;

use crate::error::{JjError, Result};
use crate::log::CommitInfo;
use crate::workspace::JjWorkspace;

impl JjWorkspace {
    /// Set the description (commit message) of the commit `revset` resolves to,
    /// returning metadata for the rewritten commit.
    ///
    /// `revset` must resolve to exactly one commit. Rewriting a commit changes
    /// its id, so descendants are rebased onto the rewrite within the same
    /// transaction; the change id is preserved.
    ///
    /// This updates the repository view only. It does not refresh any
    /// workspace's on-disk working copy — for a description-only rewrite the
    /// tree is unchanged, so the sole effect is metadata staleness that `jj`
    /// reconciles on the next CLI invocation in that workspace.
    pub fn describe(&self, revset: &str, message: &str) -> Result<CommitInfo> {
        let repo = self.repo_at_head()?;
        let target = self.resolve_single(repo.as_ref(), revset)?;
        let op_description = format!("describe commit {}", target.id().hex());

        let mut tx = repo.start_transaction();
        let rewritten = pollster::block_on(async {
            let rewritten = {
                let mut_repo = tx.repo_mut();
                let rewritten = mut_repo
                    .rewrite_commit(&target)
                    .set_description(message)
                    .write()
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
                rewritten
            };
            tx.commit(op_description)
                .await
                .map_err(|source| JjError::Transaction {
                    operation: "describe".to_owned(),
                    source: Box::new(source),
                })?;
            Ok::<_, JjError>(rewritten)
        })?;

        Ok(CommitInfo::from_commit(&rewritten))
    }
}
