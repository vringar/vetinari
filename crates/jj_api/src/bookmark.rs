//! Bookmark operations: create, move, and list local bookmarks.
//!
//! Bookmarks are jj's named pointers to commits (git calls them branches).
//! Creating or moving one only updates the repository view — no commit is
//! rewritten — so, unlike `describe` and `rebase`, these transactions need no
//! descendant rebase.

use jj_lib::object_id::ObjectId;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::RefName;

use crate::error::{JjError, Result};
use crate::workspace::JjWorkspace;

/// One local bookmark and where it points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkInfo {
    /// Bookmark name.
    pub name: String,
    /// Full id of the commit it points at, or `None` if the bookmark is
    /// conflicted (points at several commits at once).
    pub target: Option<String>,
}

impl JjWorkspace {
    /// Create a new local bookmark `name` pointing at the commit `revset`
    /// resolves to.
    ///
    /// Errors with [`JjError::BookmarkExists`] if a local bookmark of that name
    /// already exists — use [`JjWorkspace::bookmark_move`] to repoint one.
    pub fn bookmark_create(&self, name: &str, revset: &str) -> Result<()> {
        let repo = self.repo_at_head()?;
        let ref_name = RefName::new(name);
        if repo.view().get_local_bookmark(ref_name).is_present() {
            return Err(JjError::BookmarkExists {
                name: name.to_owned(),
            });
        }
        let target = self.resolve_single(repo.as_ref(), revset)?;

        let mut tx = repo.start_transaction();
        tx.repo_mut()
            .set_local_bookmark_target(ref_name, RefTarget::normal(target.id().clone()));
        pollster::block_on(tx.commit(format!("create bookmark {name}"))).map_err(|source| {
            JjError::Transaction {
                operation: "bookmark_create".to_owned(),
                source: Box::new(source),
            }
        })?;
        Ok(())
    }

    /// Repoint the existing local bookmark `name` at the commit `revset`
    /// resolves to.
    ///
    /// Errors with [`JjError::BookmarkMissing`] if no such bookmark exists.
    pub fn bookmark_move(&self, name: &str, revset: &str) -> Result<()> {
        let repo = self.repo_at_head()?;
        let ref_name = RefName::new(name);
        if repo.view().get_local_bookmark(ref_name).is_absent() {
            return Err(JjError::BookmarkMissing {
                name: name.to_owned(),
            });
        }
        let target = self.resolve_single(repo.as_ref(), revset)?;

        let mut tx = repo.start_transaction();
        tx.repo_mut()
            .set_local_bookmark_target(ref_name, RefTarget::normal(target.id().clone()));
        pollster::block_on(tx.commit(format!("move bookmark {name}"))).map_err(|source| {
            JjError::Transaction {
                operation: "bookmark_move".to_owned(),
                source: Box::new(source),
            }
        })?;
        Ok(())
    }

    /// Forget the local bookmark `name`, leaving any remote branch it was
    /// pushed to untouched.
    ///
    /// This clears only the *local* bookmark pointer (by setting its target
    /// absent). It does **not** push a deletion, so a branch already pushed to a
    /// git remote — e.g. a `vdd/<id>-<slug>` PR head — stays on the remote. Used
    /// to reap the orchestrator's per-issue landing bookmark after a successful
    /// push + PR so the local repository does not accrue one dead bookmark per
    /// landed issue. Idempotent: forgetting an absent bookmark is a no-op.
    pub fn bookmark_forget(&self, name: &str) -> Result<()> {
        let repo = self.repo_at_head()?;
        let ref_name = RefName::new(name);
        if repo.view().get_local_bookmark(ref_name).is_absent() {
            return Ok(());
        }
        let mut tx = repo.start_transaction();
        tx.repo_mut()
            .set_local_bookmark_target(ref_name, RefTarget::absent());
        pollster::block_on(tx.commit(format!("forget bookmark {name}"))).map_err(|source| {
            JjError::Transaction {
                operation: "bookmark_forget".to_owned(),
                source: Box::new(source),
            }
        })?;
        Ok(())
    }

    /// List every local bookmark, sorted by name.
    pub fn bookmark_list(&self) -> Result<Vec<BookmarkInfo>> {
        let repo = self.repo_at_head()?;
        let mut bookmarks: Vec<BookmarkInfo> = repo
            .view()
            .local_bookmarks()
            .map(|(name, target)| BookmarkInfo {
                name: String::from(name),
                target: target.as_normal().map(ObjectId::hex),
            })
            .collect();
        bookmarks.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(bookmarks)
    }
}
