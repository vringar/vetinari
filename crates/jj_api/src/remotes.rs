//! Reading git remote configuration through jj's git backend.
//!
//! jj stores its git remotes in the backing git repository's config. The
//! orchestrator needs the *URL* of a configured remote so remote-mode landing
//! can derive the GitHub `owner/repo` the PR is opened against from the SAME
//! remote the branch is pushed to (rather than an independent env var) — see the
//! landing module's `for_remote` opener. This reads the `remote.<name>.url` git
//! config value via `jj_lib::git::get_git_repo`; no `git`/`jj` subprocess is
//! spawned (jj-lib hands back an in-process `gix` repository handle).

use jj_lib::repo::Repo;

use crate::error::{JjError, Result};
use crate::workspace::JjWorkspace;

impl JjWorkspace {
    /// The fetch URL configured for the git remote `remote`, or `None` if the
    /// remote is not configured (or has no URL).
    ///
    /// Reads `remote.<name>.url` from the backing git repository's config
    /// through jj's git backend. A non-git backend (jj can, in principle, use a
    /// native backend) surfaces as [`JjError::Backend`].
    pub fn remote_url(&self, remote: &str) -> Result<Option<String>> {
        let repo = self.repo_at_head()?;
        let git_repo =
            jj_lib::git::get_git_repo(repo.store()).map_err(|source| JjError::Backend {
                source: Box::new(source),
            })?;
        let key = format!("remote.{remote}.url");
        Ok(git_repo
            .config_snapshot()
            .string(key.as_str())
            .map(|value| value.to_string()))
    }
}
