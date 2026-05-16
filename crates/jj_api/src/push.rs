//! The `git_push` operation: push a local bookmark to a git remote.
//!
//! `jj-lib` runs the actual `git` binary as a subprocess internally, so this
//! crate links no git library and shells out to nothing itself — the AC-24
//! "no shell-out" lint stays satisfied.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use jj_lib::git::{
    push_refs, GitProgress, GitPushOptions, GitPushRefTargets, GitPushStats,
    GitSidebandLineTerminator, GitSubprocessCallback, GitSubprocessOptions,
};
use jj_lib::merge::Diff;
use jj_lib::ref_name::{RefName, RefNameBuf, RemoteName, RemoteRefSymbol};

use crate::error::{JjError, Result};
use crate::workspace::JjWorkspace;

impl JjWorkspace {
    /// Push the local bookmark `bookmark` to the git remote `remote`.
    ///
    /// jj performs a compare-and-swap against the position it last observed
    /// for the remote-tracking ref. If the remote has diverged from that
    /// position the push is rejected and this returns [`JjError::PushRejected`]
    /// without advancing anything — the orchestrator's cue to fetch and rebase.
    ///
    /// Errors with [`JjError::BookmarkMissing`] if `bookmark` is not a local
    /// bookmark.
    pub fn git_push(&self, remote: &str, bookmark: &str) -> Result<()> {
        let repo = self.repo_at_head()?;
        let remote_name = RemoteName::new(remote);
        let ref_name = RefName::new(bookmark);

        let new_target = repo
            .view()
            .get_local_bookmark(ref_name)
            .as_normal()
            .cloned()
            .ok_or_else(|| JjError::BookmarkMissing {
                name: bookmark.to_owned(),
            })?;
        // The expected remote position: whatever jj last recorded for the
        // remote-tracking ref. `None` means "expected absent" — a first push.
        let expected_remote_target = repo
            .view()
            .get_remote_bookmark(RemoteRefSymbol {
                name: ref_name,
                remote: remote_name,
            })
            .target
            .as_normal()
            .cloned();

        let targets = GitPushRefTargets {
            bookmarks: vec![(
                RefNameBuf::from(bookmark),
                Diff::new(expected_remote_target, Some(new_target)),
            )],
            tags: vec![],
        };
        // Resolve `git` from PATH; the orchestrator's ambient git configuration
        // (credentials, askpass) applies. jj-lib runs the subprocess itself.
        let subprocess_options = GitSubprocessOptions {
            executable_path: PathBuf::from("git"),
            environment: HashMap::new(),
        };
        let push_options = GitPushOptions::default();

        let mut tx = repo.start_transaction();
        let mut callback = SilentCallback;
        let stats = push_refs(
            tx.repo_mut(),
            subprocess_options,
            remote_name,
            &targets,
            &mut callback,
            &push_options,
        )
        .map_err(|source| JjError::PushFailed {
            remote: remote.to_owned(),
            source: Box::new(source),
        })?;

        if !stats.all_ok() {
            // The remote-tracking ref did not advance; drop the transaction
            // unpublished so the repository view is left untouched.
            return Err(JjError::PushRejected {
                remote: remote.to_owned(),
                summary: summarize_rejections(&stats),
            });
        }
        pollster::block_on(tx.commit(format!("push bookmark {bookmark} to {remote}"))).map_err(
            |source| JjError::Transaction {
                operation: "git_push".to_owned(),
                source: Box::new(source),
            },
        )?;
        Ok(())
    }
}

/// One-line summary of every ref a push rejected, for [`JjError::PushRejected`].
fn summarize_rejections(stats: &GitPushStats) -> String {
    let format_one =
        |(name, reason): &(jj_lib::ref_name::GitRefNameBuf, Option<String>)| match reason {
            Some(reason) => format!("{} ({reason})", name.as_str()),
            None => name.as_str().to_owned(),
        };
    let mut parts: Vec<String> = Vec::new();
    parts.extend(stats.rejected.iter().map(format_one));
    parts.extend(stats.remote_rejected.iter().map(format_one));
    if parts.is_empty() {
        "push rejected".to_owned()
    } else {
        parts.join(", ")
    }
}

/// A [`GitSubprocessCallback`] that discards all progress and sideband output.
/// The orchestrator captures git's outcome from [`GitPushStats`], not its
/// chatter.
struct SilentCallback;

impl GitSubprocessCallback for SilentCallback {
    fn needs_progress(&self) -> bool {
        false
    }

    fn progress(&mut self, _progress: &GitProgress) -> io::Result<()> {
        Ok(())
    }

    fn local_sideband(
        &mut self,
        _message: &[u8],
        _terminator: Option<GitSidebandLineTerminator>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn remote_sideband(
        &mut self,
        _message: &[u8],
        _terminator: Option<GitSidebandLineTerminator>,
    ) -> io::Result<()> {
        Ok(())
    }
}
