//! The [`JjWorkspace`] handle: loading a jj workspace and the shared helpers
//! every adapter operation builds on.

use std::path::Path;
use std::sync::Arc;

use jj_lib::config::{ConfigLayer, ConfigSource, StackedConfig};
use jj_lib::repo::{ReadonlyRepo, StoreFactories};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{default_working_copy_factories, Workspace};

use crate::error::{JjError, Result};

/// Identity the orchestrator commits under when it rewrites or creates commits
/// (describe, rebase, bookmark moves). The *author* of a rewritten commit is
/// always preserved by `jj-lib`; only the committer reflects this identity, so
/// the operation log records that the orchestrator — not a worker — touched it.
const ORCHESTRATOR_USER_NAME: &str = "vetinari-orchestrator";
/// Committer email paired with [`ORCHESTRATOR_USER_NAME`]. The `.invalid` TLD
/// is reserved by RFC 2606 and can never resolve to a real mailbox.
pub(crate) const ORCHESTRATOR_USER_EMAIL: &str = "orchestrator@vetinari.invalid";

/// A loaded jj workspace. This is the single entry point of the adapter: every
/// operation the orchestrator performs is a method on this handle.
///
/// The handle is cheap to keep around; it does *not* pin a repository view.
/// Each operation loads the repository at its current head operation so a
/// long-lived handle never observes a stale view.
pub struct JjWorkspace {
    /// The underlying `jj-lib` workspace. Crate-visible so the per-operation
    /// modules (`log`, `status`, …) can reach it.
    pub(crate) workspace: Workspace,
}

impl JjWorkspace {
    /// Load the jj workspace rooted at `path`.
    ///
    /// `path` must be a directory inside a jj repository (one containing a
    /// `.jj/` directory, possibly an ancestor of `path`).
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let settings = build_settings()?;
        let store_factories = StoreFactories::default();
        let working_copy_factories = default_working_copy_factories();
        let workspace = Workspace::load(&settings, path, &store_factories, &working_copy_factories)
            .map_err(|source| JjError::WorkspaceLoad {
                path: path.to_path_buf(),
                source: Box::new(source),
            })?;
        Ok(Self { workspace })
    }

    /// Absolute path of this workspace's root directory.
    pub fn workspace_root(&self) -> &Path {
        self.workspace.workspace_root()
    }

    /// Load the repository at its current head operation.
    ///
    /// Every read operation calls this so it observes the latest view; write
    /// operations call it to obtain the base for a fresh transaction.
    pub(crate) fn repo_at_head(&self) -> Result<Arc<ReadonlyRepo>> {
        pollster::block_on(self.workspace.repo_loader().load_at_head()).map_err(|source| {
            JjError::RepoLoad {
                source: Box::new(source),
            }
        })
    }
}

/// Build the [`UserSettings`] the workspace and its transactions run under.
///
/// `jj-lib`'s built-in defaults supply everything except a user identity, which
/// jj never defaults (it forces every user to set one). We inject the fixed
/// orchestrator identity so commit rewrites have a committer signature.
fn build_settings() -> Result<UserSettings> {
    let mut config = StackedConfig::with_defaults();
    let identity = format!(
        "user.name = {ORCHESTRATOR_USER_NAME:?}\nuser.email = {ORCHESTRATOR_USER_EMAIL:?}\n"
    );
    let layer =
        ConfigLayer::parse(ConfigSource::Repo, &identity).map_err(|source| JjError::Settings {
            source: Box::new(source),
        })?;
    config.add_layer(layer);
    UserSettings::from_config(config).map_err(|source| JjError::Settings {
        source: Box::new(source),
    })
}
