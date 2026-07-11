//! Shared test support: stands up the `hello` dogfood fixture (AC-11a).
//!
//! [`build_fixture`] materializes a self-contained jj + crosslink repository in
//! a temp dir from the committed source at `tests/fixtures/hello`, seeded with
//! one `phase:graphed` issue and an agent signing identity, in local landing
//! mode (`tracker_remote` empty). This is test-support code, so it drives the
//! `jj` and `crosslink` CLIs directly — crosslink exposes no repo-provisioning
//! library surface, and the AC-24 no-shell-out lint scopes to `src/**` only.

#![allow(dead_code)] // not every test binary uses every helper

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// A materialized dogfood fixture. The repository is removed when this value is
/// dropped, so hold it for the lifetime of the test.
pub struct Fixture {
    /// Repository root (the directory containing `.jj/`, `.crosslink/`, and the
    /// `hello` crate source).
    pub root: PathBuf,
    /// The seed issue's crosslink id.
    pub issue_id: i64,
    _tmp: TempDir,
}

/// Run `program args...` in `cwd`, returning captured stdout (trimmed) and
/// panicking with captured output on failure.
fn run_capture(program: &str, args: &[&str], cwd: &Path) -> String {
    let out = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn `{program}`: {e}"));
    assert!(
        out.status.success(),
        "`{program} {}` failed in {} ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        args.join(" "),
        cwd.display(),
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Absolute path to a committed file under `tests/fixtures/`, resolved relative
/// to this crate so it works regardless of the cwd the test runner uses.
fn fixtures_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
        .canonicalize()
        .unwrap_or_else(|e| panic!("tests/fixtures/{rel} must exist: {e}"))
}

/// Path to the committed fake-implementer worker script.
pub fn fake_implementer() -> PathBuf {
    fixtures_path("fake-implementer.sh")
}

/// Run `program args...` in `cwd`, panicking with captured output on failure.
fn run(program: &str, args: &[&str], cwd: &Path) {
    let out = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn `{program}`: {e}"));
    assert!(
        out.status.success(),
        "`{program} {}` failed in {} ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        args.join(" "),
        cwd.display(),
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Recursively copy the contents of `src` into `dst` (which must exist).
fn copy_dir_contents(src: &Path, dst: &Path) {
    for entry in std::fs::read_dir(src).expect("read fixture source dir") {
        let entry = entry.expect("dir entry");
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            std::fs::create_dir_all(&to).expect("create dir");
            copy_dir_contents(&from, &to);
        } else {
            std::fs::copy(&from, &to).expect("copy file");
        }
    }
}

/// Materialize the `hello` fixture: a jj-colocated repo with a `main` bookmark,
/// crosslink initialized in local landing mode, and one `phase:graphed` issue.
///
/// The crosslink scaffolding (~59 files under `.crosslink/`, `.gitignore`, etc.)
/// is folded into the `main` baseline, so the Implementer's later change is
/// code-only — otherwise local-mode landing (REQ-17) would rebase all that
/// scaffolding onto `main` a second time.
pub fn build_fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();

    // 1. copy the committed crate source into the temp repo.
    copy_dir_contents(&fixtures_path("hello"), &root);

    // 2. jj-colocated repo: describe the baseline containing the source.
    run("jj", &["git", "init"], &root);
    // NOTE: no jj user identity is configured. jj warns on commit with an empty
    // identity but still commits, and local-mode landing (rebase + fast-forward,
    // no push) does not need one. Setting a repo-local identity is avoided on
    // purpose: it trips jj 0.41's per-repo "secure config" check, which needs a
    // writable ~/.config/jj/ that some sandboxes mount read-only. When
    // remote-mode landing arrives (REQ-17), give the spawn a writable JJ config
    // via env instead.
    run("jj", &["describe", "-m", "Initial hello fixture"], &root);
    run("jj", &["new"], &root);

    // 3. crosslink init (requires the git commit jj just exported) in local
    //    landing mode — AC-11a rebases onto main rather than opening a PR. This
    //    scaffolds ~59 files into the working copy; folding them into their own
    //    commit (below) keeps them off the Implementer's change.
    run("crosslink", &["init", "--defaults", "--quiet"], &root);
    run("crosslink", &["config", "set", "tracker_remote", ""], &root);

    // 4. the seed issue, pre-graphed so the build pump picks it up (Q1: the
    //    pump ignores unphased issues). `--quiet` prints the assigned id (and
    //    nothing else) on the last line of stdout; parse it rather than assuming
    //    the first issue is always `1`.
    let create_out = run_capture(
        "crosslink",
        &[
            "issue",
            "create",
            "Add a hello-world say_hi function with a passing test",
            "-d",
            "Add `pub fn say_hi() -> &'static str` returning \"hello\", plus a unit test.",
            "-p",
            "high",
            "-l",
            "phase:graphed",
            "--quiet",
        ],
        &root,
    );
    let issue_id: i64 = create_out
        .lines()
        .last()
        .and_then(|l| l.trim().parse().ok())
        .unwrap_or_else(|| {
            panic!("could not parse issue id from `issue create` output: {create_out:?}")
        });

    // 5. fold the source + all crosslink scaffolding into the baseline, point
    //    `main` at it, and leave `@` a fresh empty change for the worker.
    run(
        "jj",
        &["describe", "-m", "Add crosslink scaffolding"],
        &root,
    );
    run("jj", &["new"], &root);
    run("jj", &["bookmark", "create", "main", "-r", "@-"], &root);

    Fixture {
        root,
        issue_id,
        _tmp: tmp,
    }
}
