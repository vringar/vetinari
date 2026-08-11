//! Shared test support: stands up the `hello` dogfood fixture (AC-11a).
//!
//! [`build_fixture`] materializes a self-contained jj + crosslink repository in
//! a temp dir from the committed source at `tests/fixtures/hello`, seeded with
//! one `phase:graphed` issue and an agent signing identity, in local landing
//! mode (`tracker_remote` empty). This is test-support code, so it drives the
//! `jj` and `crosslink` CLIs directly — crosslink exposes no repo-provisioning
//! library surface, and the AC-24 no-shell-out lint scopes to `src/**` only.

#![allow(dead_code)] // not every test binary uses every helper

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;
use vetinari_zellij_host::{session_ensure, SessionHandle};

/// Fixed path of the cross-process zellij test lockfile, under the system temp
/// dir so every test binary for this user resolves the same file.
fn zellij_lockfile() -> PathBuf {
    std::env::temp_dir().join("vetinari-zellij-test.lock")
}

/// Take the cross-process zellij lock, blocking until every other test process
/// releases it. The returned open [`File`] IS the lock: an advisory `flock(2)`
/// `LOCK_EX` is held for as long as the fd stays open and released when it is
/// dropped (closed). A per-process `Mutex` cannot do this — the `zellij` CLI
/// shares ONE per-user background server + socket, and cargo runs the test
/// BINARIES concurrently, so serialization has to be a real cross-process
/// mutex. `flock` on separate open file descriptions also blocks between
/// threads of the same process, so this alone serializes both.
fn acquire_zellij_lock() -> File {
    let path = zellij_lockfile();
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .unwrap_or_else(|e| panic!("open zellij test lockfile {}: {e}", path.display()));
    // SAFETY: `flock` only needs a valid open fd, which `file` owns for the
    // duration of the call and beyond (the caller keeps `file` alive to hold
    // the lock). `LOCK_EX` blocks until the lock is free.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    assert!(
        rc == 0,
        "flock({}) LOCK_EX failed: {}",
        path.display(),
        std::io::Error::last_os_error(),
    );
    file
}

/// Holds the cross-process zellij lock for a test and kills the ensured session
/// on drop. Hold it for the lifetime of the test alongside the [`Fixture`].
pub struct SessionGuard {
    name: String,
    // The open, flock-held lockfile. Fields drop in declaration order, so the
    // session is killed (below) BEFORE this fd closes and releases the lock —
    // the next process never sees this session mid-teardown.
    _lock: File,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let _ = Command::new("zellij")
            .args(["kill-session", &self.name])
            .output();
    }
}

/// Ensure a uniquely-named headless zellij session (serialized against every
/// other zellij-touching test PROCESS via an flock on [`zellij_lockfile`]),
/// returning the session handle and a guard that releases the lock + kills the
/// session on drop.
pub fn unique_session(tag: &str) -> (SessionHandle, SessionGuard) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let lock = acquire_zellij_lock();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("vetinari-{tag}-{}-{n}", std::process::id());
    let guard = SessionGuard {
        name: name.clone(),
        _lock: lock,
    };
    let session = session_ensure(&name).expect("ensure headless session");
    (session, guard)
}

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

/// Path to the committed fake-implementer worker script (happy path).
pub fn fake_implementer() -> PathBuf {
    fixtures_path("fake-implementer.sh")
}

/// Path to the fake implementer that always produces a QA-failing change.
pub fn fake_implementer_qa_fail() -> PathBuf {
    fixtures_path("fake-implementer-qa-fail.sh")
}

/// Path to the fake implementer that writes a valid DONE but makes no change.
pub fn fake_implementer_empty() -> PathBuf {
    fixtures_path("fake-implementer-empty.sh")
}

/// Path to the committed fake-adversary worker script: reads the pre-rendered
/// `_orchestrator/diff.patch` and writes a canned `findings.jsonl` + DONE (A1).
pub fn fake_adversary() -> PathBuf {
    fixtures_path("fake-adversary.sh")
}

/// Path to the CONTENT-DRIVEN fake implementer for the AC-15 iteration-2 E2E
/// (A4): writes the FLAWED variant (an `unsafe { }` block calling `get_unchecked`
/// behind a safe-looking API) on the first round, and the FIXED variant (safe
/// indexing, no unsafe) once the ORCHESTRATOR delivers a prior Adversary finding
/// into its workspace (`_orchestrator/prior_findings.jsonl`, REQ-8). Its output
/// is driven by review content, not a round counter.
pub fn fake_implementer_unsafe() -> PathBuf {
    fixtures_path("fake-implementer-unsafe.sh")
}

/// Path to the CONTENT-DRIVEN fake adversary for the AC-15 iteration-2 E2E (A4):
/// reads the pre-rendered `_orchestrator/diff.patch` and FLAGS a finding IFF the
/// flaw's distinctive `get_unchecked` marker is present in the diff, signing off
/// CLEAN once it is gone. Its verdict is driven by the actual change, closing the
/// loop honestly; it records nothing outside its own `_orchestrator/` outputs.
pub fn fake_adversary_unsafe() -> PathBuf {
    fixtures_path("fake-adversary-unsafe.sh")
}

/// Path to the fake adversary that found NOTHING: writes an EMPTY (but
/// DONE-declared) `findings.jsonl` — a valid clean/converged round (REQ-10).
pub fn fake_adversary_clean() -> PathBuf {
    fixtures_path("fake-adversary-clean.sh")
}

/// Path to the BROKEN fake adversary that writes DONE but never produces
/// `findings.jsonl` — an incomplete round the strict reader must reject.
pub fn fake_adversary_no_findings() -> PathBuf {
    fixtures_path("fake-adversary-no-findings.sh")
}

/// Path to the fake adversary that FLAGS a finding on round 0 (empty
/// `prior_findings.json`) then signs off CLEAN on round 1+ (prior findings
/// present) — drives the re-implement-on-findings → converge cycle (A2).
pub fn fake_adversary_flag() -> PathBuf {
    fixtures_path("fake-adversary-flag.sh")
}

/// Path to the committed fake-merger worker script (REQ-19, L4): resolves the
/// fixture rebase conflict in `src/lib.rs`, snapshots the resolution, and writes
/// `merge_result.md` + DONE.
pub fn fake_merger() -> PathBuf {
    fixtures_path("fake-merger.sh")
}

/// Path to the fake merger that FAILS to resolve: it writes a valid DONE but
/// leaves the conflict markers in place, so the orchestrator's post-merge
/// conflict check parks the issue at `phase:awaiting-human-merge` (AC-14).
pub fn fake_merger_unresolved() -> PathBuf {
    fixtures_path("fake-merger-unresolved.sh")
}

/// Path to a CLEAN fake adversary that also records the `.workspace/` listing it
/// observed while running, into `.orchestrator/adversary-workspaces-seen.txt` —
/// proving the Implementer workspace was forgotten before review (#1).
pub fn fake_adversary_clean_record() -> PathBuf {
    fixtures_path("fake-adversary-clean-record.sh")
}

/// Path to the A3 mid-streak reset fake adversary: CLEAN on call 0 (streak → 1),
/// FLAG on call 1 (reset streak, re-implement), CLEAN thereafter. Drives the
/// diff-stability / streak-reset convergence test (a mid-streak finding forces a
/// fresh N-consecutive-clean run). Uses a persisted counter under `.orchestrator/`.
pub fn fake_adversary_flag_midstreak() -> PathBuf {
    fixtures_path("fake-adversary-flag-midstreak.sh")
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

    // 2. stand up the jj + crosslink repo around it and seed the graphed issue.
    let issue_id = seed_repo(&root);

    Fixture {
        root,
        issue_id,
        _tmp: tmp,
    }
}

/// The repository root of *this* workspace (two levels above the crate
/// manifest: `crates/orchestrator` → `crates` → root). Used to source the
/// pinned `npins/` a target fixture reuses for its dev shell.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must resolve")
}

/// AC-11b — materialize a **shell.nix-bearing, real-cargo** target repo the
/// orchestrator can drive to `merged`, generalizing [`build_fixture`].
///
/// Identical to the `hello` fixture (same crate, same `.orchestrator/static_qa.sh`
/// running `cargo test`, same one `phase:graphed` say_hi issue, jj-git-colocated
/// with a `main` bookmark, crosslink in local landing mode) with three additions
/// a **live `claude`** Implementer needs that the bare `hello` fixture lacks:
///
/// 1. a real `shell.nix` (copied from `tests/fixtures/ac11b-target-shell.nix`)
///    so `nix-shell <workspace>/shell.nix` inside the worker's bwrap sandbox
///    enters a dev shell with the pinned cargo + jujutsu (the [`WorkerCommand::Claude`]
///    path fails early without it — see `spawn::Spawner::spawn`);
/// 2. this repo's `npins/` beside it, so that `shell.nix`'s `import ./npins`
///    resolves to the exact pinned toolchain (reuse, no re-pin);
/// 3. `.orchestrator/config.toml` selecting the worker: `[worker] kind`
///    (`"claude"` for the live run, `"direct"` for the deterministic variant).
///
/// The shell.nix + npins are committed into the `main` baseline (folded with the
/// crosslink scaffolding), so a worker's later say_hi change stays code-only and
/// lands as a clean fast-forward, exactly as in [`build_fixture`].
pub fn build_target_fixture(config_toml: &str) -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();

    // 1. the same real-cargo crate the hello dogfood uses (Cargo.toml,
    //    Cargo.lock, src/lib.rs, .orchestrator/static_qa.sh, .gitignore).
    copy_dir_contents(&fixtures_path("hello"), &root);

    // 2. a real dev shell + the pinned sources it imports, so a live claude
    //    worker gets cargo/jj inside its sandbox (reuse this repo's toolchain).
    std::fs::copy(
        fixtures_path("ac11b-target-shell.nix"),
        root.join("shell.nix"),
    )
    .expect("copy target shell.nix");
    let npins_dst = root.join("npins");
    std::fs::create_dir_all(&npins_dst).expect("mk npins dir");
    copy_dir_contents(&workspace_root().join("npins"), &npins_dst);

    // 3. the worker-kind config the pump reads (S7). `.orchestrator/` already
    //    exists (static_qa.sh); drop config.toml beside it.
    std::fs::write(root.join(".orchestrator").join("config.toml"), config_toml)
        .expect("write config.toml");

    // 4. stand up the jj + crosslink repo and seed the graphed issue. The
    //    shell.nix + npins + config.toml are in the tree, so they fold into the
    //    `main` baseline and never appear in the Implementer's change.
    let issue_id = seed_repo(&root);

    Fixture {
        root,
        issue_id,
        _tmp: tmp,
    }
}

/// Stand up the jj-colocated + crosslink repository around an already-populated
/// `root`, point `main` at the folded baseline, and seed one `phase:graphed`
/// say_hi issue. Returns the issue's crosslink id. Shared by [`build_fixture`]
/// and [`build_target_fixture`].
fn seed_repo(root: &Path) -> i64 {
    // jj-colocated repo: describe the baseline containing the source.
    run("jj", &["git", "init"], root);
    // NOTE: no jj user identity is configured. jj warns on commit with an empty
    // identity but still commits, and local-mode landing (rebase + fast-forward,
    // no push) does not need one. Setting a repo-local identity is avoided on
    // purpose: it trips jj 0.41's per-repo "secure config" check, which needs a
    // writable ~/.config/jj/ that some sandboxes mount read-only. When
    // remote-mode landing arrives (REQ-17), give the spawn a writable JJ config
    // via env instead.
    run("jj", &["describe", "-m", "Initial fixture baseline"], root);
    run("jj", &["new"], root);

    // crosslink init (requires the git commit jj just exported) in local landing
    // mode — AC-11a/AC-11b rebase onto main rather than opening a PR. This
    // scaffolds ~59 files into the working copy; folding them into their own
    // commit (below) keeps them off the Implementer's change.
    run("crosslink", &["init", "--defaults", "--quiet"], root);
    run("crosslink", &["config", "set", "tracker_remote", ""], root);

    // the seed issue, pre-graphed so the build pump picks it up (Q1: the pump
    // ignores unphased issues). `--quiet` prints the assigned id (and nothing
    // else) on the last line of stdout; parse it rather than assuming the first
    // issue is always `1`.
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
        root,
    );
    let issue_id: i64 = create_out
        .lines()
        .last()
        .and_then(|l| l.trim().parse().ok())
        .unwrap_or_else(|| {
            panic!("could not parse issue id from `issue create` output: {create_out:?}")
        });

    // fold the source + all scaffolding into the baseline, point `main` at it,
    // and leave `@` a fresh empty change for the worker.
    run("jj", &["describe", "-m", "Add crosslink scaffolding"], root);
    run("jj", &["new"], root);
    run("jj", &["bookmark", "create", "main", "-r", "@-"], root);

    issue_id
}
