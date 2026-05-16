//! Workspace lifecycle operations: add, forget, and list.
//!
//! The orchestrator gives each worker its own jj workspace — a separate
//! working-copy directory sharing the one repository. These operations create
//! and tear down those workspaces.

use std::path::Path;

use jj_lib::object_id::ObjectId;
use jj_lib::ref_name::WorkspaceNameBuf;
use jj_lib::workspace::{default_working_copy_factory, Workspace};
use jj_lib::workspace_store::{SimpleWorkspaceStore, WorkspaceStore};

use crate::error::{JjError, Result};
use crate::workspace::JjWorkspace;

/// One workspace and its working-copy commit, as reported by
/// [`JjWorkspace::workspace_list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEntry {
    /// Workspace name.
    pub name: String,
    /// Full id of the workspace's working-copy commit.
    pub working_copy_id: String,
}

impl JjWorkspace {
    /// Create a new workspace named `name`, rooted at `path`, whose working
    /// copy starts on a fresh empty commit based at `base_revset`.
    ///
    /// `path` is created if it does not exist. `base_revset` must resolve to
    /// exactly one commit; the new workspace's files on disk are checked out to
    /// match that commit's tree, so a worker spawned there sees the base
    /// content immediately.
    pub fn workspace_add(&self, path: &Path, name: &str, base_revset: &str) -> Result<()> {
        let repo = self.repo_at_head()?;
        let base = self.resolve_single(repo.as_ref(), base_revset)?;
        let name_buf = WorkspaceNameBuf::from(name);

        // The workspace root must exist before jj can create `.jj/` inside it.
        std::fs::create_dir_all(path).map_err(|source| workspace_add_error(path, source))?;

        // init_workspace_with_existing_repo registers the workspace and checks
        // out the (empty) root commit for it.
        let working_copy_factory = default_working_copy_factory();
        let (mut new_workspace, repo) =
            pollster::block_on(Workspace::init_workspace_with_existing_repo(
                path,
                self.workspace.repo_path(),
                &repo,
                working_copy_factory.as_ref(),
                name_buf.clone(),
            ))
            .map_err(|source| workspace_add_error(path, source))?;

        // Repoint the new workspace at a fresh empty commit on `base`.
        let base_tree = base.tree();
        let mut tx = repo.start_transaction();
        let (new_commit, repo) = pollster::block_on(async {
            let new_commit = tx
                .repo_mut()
                .new_commit(vec![base.id().clone()], base_tree)
                .write()
                .await
                .map_err(|source| workspace_add_error(path, source))?;
            tx.repo_mut()
                .set_wc_commit(name_buf.clone(), new_commit.id().clone())
                .map_err(|source| workspace_add_error(path, source))?;
            let repo = tx
                .commit(format!("create initial commit for workspace {name}"))
                .await
                .map_err(|source| workspace_add_error(path, source))?;
            Ok::<_, JjError>((new_commit, repo))
        })?;

        // Materialize the base tree in the new workspace's files on disk.
        pollster::block_on(new_workspace.check_out(repo.op_id().clone(), None, &new_commit))
            .map_err(|source| workspace_add_error(path, source))?;
        Ok(())
    }

    /// Forget the workspace named `name`: drop its working-copy commit from the
    /// repository view and remove it from the workspace store.
    ///
    /// This does not delete `name`'s directory on disk — cleaning up the
    /// directory is the caller's responsibility.
    pub fn workspace_forget(&self, name: &str) -> Result<()> {
        let repo = self.repo_at_head()?;
        let name_buf = WorkspaceNameBuf::from(name);
        if repo.view().get_wc_commit_id(&name_buf).is_none() {
            return Err(JjError::WorkspaceForget {
                name: name.to_owned(),
                source: format!("no workspace named `{name}`").into(),
            });
        }

        let workspace_store = SimpleWorkspaceStore::load(self.workspace.repo_path())
            .map_err(|source| workspace_forget_error(name, source))?;

        let mut tx = repo.start_transaction();
        pollster::block_on(tx.repo_mut().remove_wc_commit(&name_buf))
            .map_err(|source| workspace_forget_error(name, source))?;
        workspace_store
            .forget(&[name_buf.as_ref()])
            .map_err(|source| workspace_forget_error(name, source))?;
        pollster::block_on(tx.commit(format!("forget workspace {name}")))
            .map_err(|source| workspace_forget_error(name, source))?;
        Ok(())
    }

    /// List every workspace in the repository, sorted by name.
    pub fn workspace_list(&self) -> Result<Vec<WorkspaceEntry>> {
        let repo = self.repo_at_head()?;
        // `wc_commit_ids` is a BTreeMap, so iteration is already name-sorted.
        Ok(repo
            .view()
            .wc_commit_ids()
            .iter()
            .map(|(name, commit_id)| WorkspaceEntry {
                name: String::from(name),
                working_copy_id: commit_id.hex(),
            })
            .collect())
    }
}

/// Wrap an underlying failure as a [`JjError::WorkspaceAdd`] for `path`.
fn workspace_add_error(
    path: &Path,
    source: impl std::error::Error + Send + Sync + 'static,
) -> JjError {
    JjError::WorkspaceAdd {
        path: path.to_path_buf(),
        source: Box::new(source),
    }
}

/// Wrap an underlying failure as a [`JjError::WorkspaceForget`] for `name`.
fn workspace_forget_error(
    name: &str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> JjError {
    JjError::WorkspaceForget {
        name: name.to_owned(),
        source: Box::new(source),
    }
}
