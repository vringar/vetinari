//! The `diff` operation: a `git diff`-format patch between two revisions.
//!
//! `jj-lib` exposes the diff *building blocks* (`git_diff_part`,
//! `unified_diff_hunks`) but not the assembly into a `diff --git` patch — that
//! lives in the `jj` CLI. This module ports that assembly, writing plain text
//! instead of a colored CLI `Formatter`.

use std::sync::Arc;

use bstr::BStr;
use futures::StreamExt;
use jj_lib::conflict_labels::ConflictLabels;
use jj_lib::conflicts::{
    materialized_diff_stream, ConflictMarkerStyle, ConflictMaterializeOptions,
    MaterializedTreeDiffEntry,
};
use jj_lib::copies::{CopyOperation, CopyRecords};
use jj_lib::diff_presentation::unified::{
    git_diff_part, unified_diff_hunks, DiffLineType, GitDiffPart,
};
use jj_lib::diff_presentation::LineCompareMode;
use jj_lib::matchers::EverythingMatcher;
use jj_lib::merge::Diff;
use jj_lib::merged_tree::MergedTree;
use jj_lib::repo::Repo;
use jj_lib::store::Store;

use crate::error::{JjError, Result};
use crate::workspace::JjWorkspace;

/// Number of unchanged context lines shown around each hunk — Git's default.
const DIFF_CONTEXT_LINES: usize = 3;

impl JjWorkspace {
    /// Render a `git diff`-format patch describing how the tree of `to`
    /// differs from the tree of `from`.
    ///
    /// `from` and `to` are revsets that must each resolve to exactly one
    /// commit. To diff a single commit against its parent, pass its parent as
    /// `from` (e.g. `from = "X-"`, `to = "X"`).
    ///
    /// The returned patch uses `a/` and `b/` path prefixes. Output is decoded
    /// lossily, so a stray non-UTF-8 byte in a file flagged as text becomes the
    /// replacement character rather than failing the whole operation.
    pub fn diff(&self, from: &str, to: &str) -> Result<String> {
        let repo = self.repo_at_head()?;
        let from_commit = self.resolve_single(repo.as_ref(), from)?;
        let to_commit = self.resolve_single(repo.as_ref(), to)?;
        render_git_diff(repo.store(), &from_commit.tree(), &to_commit.tree())
    }
}

/// Assemble the full patch text for `from_tree` -> `to_tree`.
fn render_git_diff(
    store: &Arc<Store>,
    from_tree: &MergedTree,
    to_tree: &MergedTree,
) -> Result<String> {
    let matcher = EverythingMatcher;
    // Copy/rename detection is intentionally skipped: an empty CopyRecords
    // means every change is reported as a plain add/delete/modify.
    let copy_records = CopyRecords::default();
    let tree_diff = from_tree.diff_stream_with_copies(to_tree, &matcher, &copy_records);
    let unlabeled = ConflictLabels::unlabeled();
    let conflict_labels = Diff::new(&unlabeled, &unlabeled);
    let materialize_options = ConflictMaterializeOptions {
        marker_style: ConflictMarkerStyle::Diff,
        marker_len: None,
        merge: store.merge_options().clone(),
    };

    let mut out = String::new();
    pollster::block_on(async {
        let mut stream = materialized_diff_stream(store, tree_diff, conflict_labels);
        while let Some(MaterializedTreeDiffEntry { path, values }) = stream.next().await {
            let values = values.map_err(|source| JjError::Diff {
                source: Box::new(source),
            })?;
            let left_path = path.source();
            let right_path = path.target();
            let left_part = git_diff_part(left_path, values.before, &materialize_options)
                .await
                .map_err(|source| JjError::Diff {
                    source: Box::new(source),
                })?;
            let right_part = git_diff_part(right_path, values.after, &materialize_options)
                .await
                .map_err(|source| JjError::Diff {
                    source: Box::new(source),
                })?;
            write_file_diff(
                &mut out,
                left_path.as_internal_file_string(),
                right_path.as_internal_file_string(),
                path.copy_operation(),
                &left_part,
                &right_part,
            );
        }
        Ok::<(), JjError>(())
    })?;
    Ok(out)
}

/// Write one file's `diff --git` stanza: the header, then content hunks.
fn write_file_diff(
    out: &mut String,
    left_path: &str,
    right_path: &str,
    copy_operation: Option<CopyOperation>,
    left_part: &GitDiffPart,
    right_part: &GitDiffPart,
) {
    out.push_str(&format!("diff --git a/{left_path} b/{right_path}\n"));
    let (left_hash, right_hash) = (&left_part.hash, &right_part.hash);
    match (left_part.mode, right_part.mode) {
        (None, Some(right_mode)) => {
            out.push_str(&format!("new file mode {right_mode}\n"));
            out.push_str(&format!("index {left_hash}..{right_hash}\n"));
        }
        (Some(left_mode), None) => {
            out.push_str(&format!("deleted file mode {left_mode}\n"));
            out.push_str(&format!("index {left_hash}..{right_hash}\n"));
        }
        (Some(left_mode), Some(right_mode)) => {
            match copy_operation {
                Some(CopyOperation::Copy) => {
                    out.push_str(&format!("copy from {left_path}\n"));
                    out.push_str(&format!("copy to {right_path}\n"));
                }
                Some(CopyOperation::Rename) => {
                    out.push_str(&format!("rename from {left_path}\n"));
                    out.push_str(&format!("rename to {right_path}\n"));
                }
                None => {}
            }
            if left_mode != right_mode {
                out.push_str(&format!("old mode {left_mode}\n"));
                out.push_str(&format!("new mode {right_mode}\n"));
                if left_hash != right_hash {
                    out.push_str(&format!("index {left_hash}..{right_hash}\n"));
                }
            } else if left_hash != right_hash {
                out.push_str(&format!("index {left_hash}..{right_hash} {left_mode}\n"));
            }
        }
        (None, None) => unreachable!("a diff entry always has a present side"),
    }

    if left_part.content.contents == right_part.content.contents {
        return; // header-only stanza (e.g. a pure mode change)
    }

    let left_label = match left_part.mode {
        Some(_) => format!("a/{left_path}"),
        None => "/dev/null".to_owned(),
    };
    let right_label = match right_part.mode {
        Some(_) => format!("b/{right_path}"),
        None => "/dev/null".to_owned(),
    };
    if left_part.content.is_binary || right_part.content.is_binary {
        out.push_str(&format!(
            "Binary files {left_label} and {right_label} differ\n"
        ));
        return;
    }
    out.push_str(&format!("--- {left_label}\n"));
    out.push_str(&format!("+++ {right_label}\n"));
    write_hunks(out, left_part, right_part);
}

/// Write the `@@ ... @@` content hunks for a non-binary text change.
fn write_hunks(out: &mut String, left_part: &GitDiffPart, right_part: &GitDiffPart) {
    let contents = Diff::new(
        BStr::new(&left_part.content.contents),
        BStr::new(&right_part.content.contents),
    );
    for hunk in unified_diff_hunks(contents, DIFF_CONTEXT_LINES, LineCompareMode::Exact) {
        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            hunk_start(&hunk.left_line_range),
            hunk.left_line_range.len(),
            hunk_start(&hunk.right_line_range),
            hunk.right_line_range.len(),
        ));
        for (line_type, tokens) in &hunk.lines {
            let sigil = match line_type {
                DiffLineType::Context => ' ',
                DiffLineType::Removed => '-',
                DiffLineType::Added => '+',
            };
            out.push(sigil);
            let mut line = Vec::new();
            for (_token_type, content) in tokens {
                line.extend_from_slice(content);
            }
            out.push_str(&String::from_utf8_lossy(&line));
            let ends_with_newline = tokens
                .last()
                .is_some_and(|(_, content)| content.ends_with(b"\n"));
            if !ends_with_newline {
                out.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
}

/// First line number for a hunk range, using diff(1)'s convention that an
/// empty range reports the preceding line (its `start`) rather than `start+1`.
fn hunk_start(range: &std::ops::Range<usize>) -> usize {
    if range.is_empty() {
        range.start
    } else {
        range.start + 1
    }
}
