//! Single-crosslink guard (AC-28a).
//!
//! vetinari and crossbridge each depend on `crosslink`, and `crosslink` pulls
//! `libsqlite3-sys` (`links = "sqlite3"`). cargo forbids two packages sharing a
//! `links` value, so the whole dependency graph must resolve to exactly ONE
//! `crosslink`. The workspace `[patch]` collapses crossbridge's crosslink
//! git-dependency onto vetinari's single copy to make that true.
//!
//! This check is the guardrail that makes a future divergence fail *loudly*:
//! it runs `cargo metadata` and fails the build if more than one distinct
//! `crosslink` package resolves in the graph. Without it, a crosslink-rev drift
//! would surface only as a confusing deep `links`-collision link error (or, if
//! the collision were somehow avoided, as two silently-different crosslink
//! copies). With it, `just lint` says exactly what is wrong.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Run the guard: `cargo metadata`, then assert exactly one crosslink resolves.
/// Returns `true` when clean; the caller maps this to a process exit code.
pub fn run() -> bool {
    let root = workspace_root();
    let json = match cargo_metadata(&root) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("xtask check-crosslink: could not run `cargo metadata`: {e}");
            return false;
        }
    };
    match crosslink_packages(&json) {
        Ok(found) => report(&found),
        Err(e) => {
            eprintln!("xtask check-crosslink: could not parse `cargo metadata` output: {e}");
            false
        }
    }
}

/// The workspace root, two directories above this crate's manifest
/// (`crates/xtask` → `crates` → root).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask manifest lives two levels below the workspace root")
        .to_path_buf()
}

/// Invoke `cargo metadata` for the full resolved graph (with dependencies) and
/// return its JSON on stdout.
fn cargo_metadata(root: &Path) -> Result<String, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(root)
        .args(["metadata", "--format-version", "1"])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| e.to_string())
}

/// Every distinct `crosslink` package in the resolved graph, identified by its
/// cargo package id (unique per name+version+source). Returned sorted and
/// de-duplicated, so the length is the number of distinct crosslink copies.
///
/// Split out from [`run`] so the counting logic is unit-tested against fixed
/// `cargo metadata` fixtures without invoking cargo.
fn crosslink_packages(metadata_json: &str) -> Result<Vec<String>, String> {
    let value: serde_json::Value =
        serde_json::from_str(metadata_json).map_err(|e| e.to_string())?;
    let packages = value
        .get("packages")
        .and_then(|p| p.as_array())
        .ok_or_else(|| "metadata has no `packages` array".to_owned())?;
    let mut ids: Vec<String> = packages
        .iter()
        .filter(|pkg| pkg.get("name").and_then(|n| n.as_str()) == Some("crosslink"))
        .map(|pkg| {
            // Prefer the package id; fall back to source+version if absent.
            pkg.get("id")
                .and_then(|i| i.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| describe_source(pkg))
        })
        .collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Human-readable `source@version` fallback identifier for a crosslink package
/// that (unexpectedly) carries no id.
fn describe_source(pkg: &serde_json::Value) -> String {
    let source = pkg.get("source").and_then(|s| s.as_str()).unwrap_or("path");
    let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("?");
    format!("{source}@{version}")
}

/// Print the result and report whether it is clean (exactly one crosslink).
fn report(found: &[String]) -> bool {
    match found.len() {
        1 => {
            println!("xtask check-crosslink: clean — exactly one crosslink resolves");
            true
        }
        0 => {
            // No crosslink at all is not the failure this guard exists for, but
            // it means the graph is not what we expect — surface it.
            eprintln!(
                "xtask check-crosslink: no `crosslink` package resolved in the graph \
                 (expected exactly one)"
            );
            false
        }
        n => {
            eprintln!(
                "xtask check-crosslink: {n} distinct `crosslink` packages resolved (AC-28a) — \
                 the graph must contain exactly ONE (libsqlite3-sys `links = \"sqlite3\"`).\n\
                 A crosslink-rev divergence has crept in; realign the pins or fix the \
                 workspace `[patch]`. Resolved copies:"
            );
            for id in found {
                eprintln!("  - {id}");
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One workspace member + one crosslink → clean.
    #[test]
    fn single_crosslink_is_clean() {
        let json = r#"{
            "packages": [
                {"name": "orchestrator", "id": "orchestrator 0.1.0 (path+file:///w)", "version": "0.1.0", "source": null},
                {"name": "crosslink", "id": "crosslink 0.9.0-beta.1 (path+file:///w/.crosslink-src/crosslink)", "version": "0.9.0-beta.1", "source": null}
            ]
        }"#;
        let found = crosslink_packages(json).expect("parses");
        assert_eq!(
            found.len(),
            1,
            "exactly one crosslink expected, got {found:?}"
        );
    }

    /// Two crosslink revs (a patch failure / rev divergence) → the guard sees
    /// two distinct packages and fails.
    #[test]
    fn two_crosslink_sources_is_flagged() {
        let json = r#"{
            "packages": [
                {"name": "crosslink", "id": "crosslink 0.9.0-beta.1 (path+file:///w/.crosslink-src/crosslink)", "version": "0.9.0-beta.1", "source": null},
                {"name": "crosslink", "id": "crosslink 0.9.0-beta.1 (git+https://github.com/Corvidae-Coding-Projects/crosslink.git?rev=e7b6ad8#e7b6ad8)", "version": "0.9.0-beta.1", "source": "git+https://github.com/Corvidae-Coding-Projects/crosslink.git?rev=e7b6ad8"}
            ]
        }"#;
        let found = crosslink_packages(json).expect("parses");
        assert_eq!(
            found.len(),
            2,
            "two distinct crosslink copies expected, got {found:?}"
        );
    }

    /// The same crosslink package listed once is not double-counted.
    #[test]
    fn no_crosslink_is_detected() {
        let json = r#"{"packages": [{"name": "serde", "id": "serde 1.0.0", "version": "1.0.0", "source": "registry+x"}]}"#;
        let found = crosslink_packages(json).expect("parses");
        assert!(found.is_empty(), "no crosslink expected, got {found:?}");
    }

    #[test]
    fn missing_packages_array_is_an_error() {
        assert!(crosslink_packages("{}").is_err());
        assert!(crosslink_packages("not json").is_err());
    }
}
