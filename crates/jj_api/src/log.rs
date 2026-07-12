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
    /// Whether this commit's tree contains conflicts. The orchestrator uses
    /// this to detect a rebase that produced conflict markers (REQ-19).
    pub has_conflict: bool,
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
            has_conflict: commit.has_conflict(),
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

    /// Resolve `revset` to metadata for **exactly one** commit, erroring if it
    /// matches zero ([`JjError::NoSuchRevision`]) or more than one
    /// ([`JjError::AmbiguousRevision`]).
    ///
    /// Unlike [`log`](Self::log), which returns every match and lets the caller
    /// pick, this enforces an unambiguous target — the semantics the landing
    /// machine needs so a divergent change id resolving to several commits is a
    /// hard error rather than a silent pick of one.
    pub fn resolve_single_info(&self, revset: &str) -> Result<CommitInfo> {
        let repo = self.repo_at_head()?;
        let commit = self.resolve_single(repo.as_ref(), revset)?;
        Ok(CommitInfo::from_commit(&commit))
    }
}
