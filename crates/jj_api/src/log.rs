//! The `log` operation and the [`CommitInfo`] type it yields.

use jj_lib::commit::Commit;
use jj_lib::object_id::ObjectId;

use crate::error::Result;
use crate::workspace::JjWorkspace;

/// Adapter-owned snapshot of a commit's metadata.
///
/// This is deliberately a plain data type with no `jj-lib` types in it, so the
/// orchestrator can hold and compare commits without linking `jj-lib`. Ids are
/// full-length lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    /// Full commit id (the content hash).
    pub commit_id: String,
    /// Full change id (stable across rewrites of the same logical change).
    pub change_id: String,
    /// Commit description / message.
    pub description: String,
    /// Author display name.
    pub author_name: String,
    /// Author email.
    pub author_email: String,
    /// Full commit ids of this commit's parents.
    pub parent_ids: Vec<String>,
}

impl CommitInfo {
    /// Project a `jj-lib` [`Commit`] onto the adapter's commit type.
    pub(crate) fn from_commit(commit: &Commit) -> Self {
        let author = commit.author();
        Self {
            commit_id: commit.id().hex(),
            change_id: commit.change_id().hex(),
            description: commit.description().to_owned(),
            author_name: author.name.clone(),
            author_email: author.email.clone(),
            parent_ids: commit.parent_ids().iter().map(ObjectId::hex).collect(),
        }
    }
}

impl JjWorkspace {
    /// Evaluate `revset` and return metadata for every matching commit.
    ///
    /// `revset` is any expression jj's revset language accepts — a commit or
    /// change id, a bookmark name, `@`, `::@`, etc. The result order is the
    /// revset engine's natural order (newest first for ancestor sets).
    pub fn log(&self, revset: &str) -> Result<Vec<CommitInfo>> {
        let repo = self.repo_at_head()?;
        let commits = self.evaluate_revset(repo.as_ref(), revset)?;
        Ok(commits.iter().map(CommitInfo::from_commit).collect())
    }
}
