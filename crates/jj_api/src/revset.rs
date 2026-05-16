//! Revset parsing/resolution/evaluation, shared by every read and write
//! operation that has to turn a revset string into concrete commits.
//!
//! The helpers here are crate-internal: they return `jj-lib`'s `Commit` type,
//! which the public operation modules immediately translate into adapter types.

use std::collections::HashMap;

use futures::TryStreamExt;
use jj_lib::commit::Commit;
use jj_lib::fileset::FilesetAliasesMap;
use jj_lib::repo::Repo;
use jj_lib::repo_path::RepoPathUiConverter;
use jj_lib::revset::{
    self, RevsetAliasesMap, RevsetDiagnostics, RevsetExtensions, RevsetParseContext,
    RevsetResolutionError, RevsetStreamExt, RevsetWorkspaceContext, SymbolResolver,
    SymbolResolverExtension,
};

use crate::error::{JjError, Result};
use crate::workspace::{JjWorkspace, ORCHESTRATOR_USER_EMAIL};

impl JjWorkspace {
    /// Parse, resolve, and evaluate `revset_str` against `repo`, returning every
    /// matching commit. The result order is whatever the revset engine yields.
    pub(crate) fn evaluate_revset(&self, repo: &dyn Repo, revset_str: &str) -> Result<Vec<Commit>> {
        // The parse context is rebuilt per call: it borrows the repo's
        // workspace root, and the alias maps are deliberately empty — the
        // orchestrator passes literal revsets, never user-defined aliases.
        let aliases_map = RevsetAliasesMap::new();
        let fileset_aliases_map = FilesetAliasesMap::new();
        let extensions = RevsetExtensions::new();
        let root = self.workspace.workspace_root().to_path_buf();
        let path_converter = RepoPathUiConverter::Fs {
            cwd: root.clone(),
            base: root,
        };
        let workspace_context = RevsetWorkspaceContext {
            path_converter: &path_converter,
            workspace_name: self.workspace.workspace_name(),
        };
        let context = RevsetParseContext {
            aliases_map: &aliases_map,
            local_variables: HashMap::new(),
            user_email: ORCHESTRATOR_USER_EMAIL,
            date_pattern_context: chrono::Local::now().into(),
            default_ignored_remote: None,
            fileset_aliases_map: &fileset_aliases_map,
            use_glob_by_default: false,
            extensions: &extensions,
            workspace: Some(workspace_context),
        };

        let mut diagnostics = RevsetDiagnostics::new();
        let expression =
            revset::parse(&mut diagnostics, revset_str, &context).map_err(|source| {
                JjError::Revset {
                    revset: revset_str.to_owned(),
                    source: Box::new(source),
                }
            })?;

        // No symbol-resolver extensions: only built-in symbols are accepted.
        let resolver_extensions: &[Box<dyn SymbolResolverExtension>] = &[];
        let symbol_resolver = SymbolResolver::new(repo, resolver_extensions);
        let resolved = expression
            .resolve_user_expression(repo, &symbol_resolver)
            .map_err(|source| map_resolution_error(revset_str, source))?;

        let revset = resolved.evaluate(repo).map_err(|source| JjError::Revset {
            revset: revset_str.to_owned(),
            source: Box::new(source),
        })?;

        pollster::block_on(
            revset
                .stream()
                .commits(repo.store())
                .try_collect::<Vec<_>>(),
        )
        .map_err(|source| JjError::Revset {
            revset: revset_str.to_owned(),
            source: Box::new(source),
        })
    }

    /// Resolve `revset_str` to exactly one commit, erroring if it matches zero
    /// or more than one. Write operations (`describe`, `rebase`, bookmark
    /// moves) and `diff` endpoints require an unambiguous target.
    pub(crate) fn resolve_single(&self, repo: &dyn Repo, revset_str: &str) -> Result<Commit> {
        let mut commits = self.evaluate_revset(repo, revset_str)?;
        match commits.len() {
            0 => Err(JjError::NoSuchRevision {
                revset: revset_str.to_owned(),
            }),
            1 => Ok(commits.pop().expect("length checked to be 1")),
            count => Err(JjError::AmbiguousRevision {
                revset: revset_str.to_owned(),
                count,
            }),
        }
    }
}

/// Translate a resolution failure: a "no such revision" becomes the dedicated
/// [`JjError::NoSuchRevision`] so callers can branch on it without string
/// matching; everything else is an opaque revset failure.
fn map_resolution_error(revset: &str, error: RevsetResolutionError) -> JjError {
    match error {
        RevsetResolutionError::NoSuchRevision { .. } => JjError::NoSuchRevision {
            revset: revset.to_owned(),
        },
        other => JjError::Revset {
            revset: revset.to_owned(),
            source: Box::new(other),
        },
    }
}
