//! Own-slug derivation (spec §1.1, review N7).
//!
//! The orchestrator needs to know its node's crossbridge slug to locate its own
//! socket directory (`<socket_root>/<own_slug>/`) when answering a peer. The
//! slug must be derived *exactly* as crossbridge's binaries derive it, or a
//! client and its peer server would disagree on what to call the repo. Rather
//! than reimplement the precedence (flag → `$CROSSBRIDGE_OWN_SLUG` → origin
//! remote), this wraps crossbridge's own `resolve_slug`, returning a plain
//! `String`.
//!
//! Note: crossbridge's derivation may shell out to `git`/`jj` to read the
//! `origin` remote. That subprocess lives entirely inside crossbridge's crate,
//! not vetinari's — this adapter constructs no `Command`, so the AC-24
//! no-shell-out audit (which scans vetinari's `crates/*/src` for
//! `Command::new` literals) is unaffected. Reusing crossbridge's derivation is
//! the point (review N7): a divergent reimplementation is the bug.

use std::path::Path;

use crate::error::{CrossbridgeError, Result};

/// Derive this node's crossbridge slug for the repository at `repo_root`.
///
/// Precedence (crossbridge's own, via `resolve_slug`):
/// 1. `override_slug` (e.g. an explicit `--slug` / config value), if `Some`;
/// 2. the `$CROSSBRIDGE_OWN_SLUG` environment variable;
/// 3. derivation from the repository's `origin` remote.
///
/// # Errors
/// Returns [`CrossbridgeError::SlugDerivation`] when `override_slug` is present
/// but blank, or when all three steps fail to produce a slug (no override, no
/// env var, and no parseable `origin` remote).
pub fn own_slug(repo_root: &Path, override_slug: Option<&str>) -> Result<String> {
    crossbridge_server::slug::resolve_slug(override_slug, |key| std::env::var_os(key), repo_root)
        .map_err(|source| CrossbridgeError::SlugDerivation {
            repo_root: repo_root.to_path_buf(),
            source: source.into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn override_wins_and_is_trimmed() {
        let slug = own_slug(Path::new("/does/not/exist"), Some("  firmware\n"))
            .expect("explicit override resolves without touching the repo");
        assert_eq!(slug, "firmware");
    }

    #[test]
    fn blank_override_is_an_error() {
        let err = own_slug(Path::new("/does/not/exist"), Some("   "))
            .expect_err("a blank override must not resolve");
        assert!(matches!(err, CrossbridgeError::SlugDerivation { .. }));
    }

    #[test]
    fn no_override_no_remote_is_an_error() {
        // `resolve_slug` consults the real `$CROSSBRIDGE_OWN_SLUG`; skip if the
        // ambient environment sets it, so the test stays hermetic.
        if std::env::var_os("CROSSBRIDGE_OWN_SLUG").is_some() {
            return;
        }
        // A path with no git/jj repo and no override: derivation fails, and we
        // surface it as our own typed error (no crossbridge type leaks).
        let err = own_slug(Path::new("/does/not/exist"), None)
            .expect_err("derivation should fail with no repo and no override");
        assert!(matches!(err, CrossbridgeError::SlugDerivation { .. }));
    }
}
