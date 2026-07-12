//! Revset parsing/resolution/evaluation, shared by every read and write
//! operation that has to turn a revset string into concrete commits.
//!
//! The helpers here are crate-internal: they return `jj-lib`'s `Commit` type,
//! which the public operation modules immediately translate into adapter types.

use std::collections::HashMap;

use futures::TryStreamExt;
use jj_lib::commit::Commit;
use jj_lib::fileset::FilesetAliasesMap;
use jj_lib::object_id::ObjectId;
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

    /// Whether the commit `ancestor` resolves to is an ancestor of (or equal to)
    /// the commit `descendant` resolves to — i.e. moving a bookmark from
    /// `ancestor` to `descendant` would be a true fast-forward.
    ///
    /// Both revsets must resolve to exactly one commit (via the same
    /// [`resolve_single`](Self::resolve_single) semantics the write ops use), so
    /// an ambiguous/divergent revset is an error rather than a silent pick. The
    /// test is the revset `ancestor & ::descendant` being non-empty: `::x` is the
    /// ancestor set of `x` (inclusive of `x`), so the intersection is non-empty
    /// exactly when `ancestor` lies on-or-below `descendant`.
    ///
    /// The load-bearing safety guard for local-mode landing: before moving the
    /// `main` bookmark, the orchestrator asserts the current `main` commit is an
    /// ancestor of the landing target, so `main` can only ever fast-forward and
    /// never rewind or move sideways (REQ-17).
    pub fn is_ancestor(&self, ancestor: &str, descendant: &str) -> Result<bool> {
        let repo = self.repo_at_head()?;
        // resolve_single pins each side to exactly one commit (erroring on an
        // ambiguous/divergent id) before we build the ancestry query, so the
        // guard can never be fooled by a revset that fans out to many commits.
        let ancestor_commit = self.resolve_single(repo.as_ref(), ancestor)?;
        let descendant_commit = self.resolve_single(repo.as_ref(), descendant)?;
        // Query by full commit id so the intersection can't be confused by a
        // revset symbol that resolves differently in this second evaluation.
        let query = format!(
            "{} & ::{}",
            ancestor_commit.id().hex(),
            descendant_commit.id().hex()
        );
        Ok(!self.evaluate_revset(repo.as_ref(), &query)?.is_empty())
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
