//! Worker spawn: host a worker in a zellij pane, in a prepared jj workspace,
//! behind a `bwrap` store-path pin guard (REQ-1d, REQ-4, REQ-4a, REQ-5,
//! REQ-13, AC-19, AC-27).
//!
//! This is the layer that turns a [`PreparedWorkspace`](crate::workspace) into
//! a running worker. It supports **two** worker command kinds behind one
//! abstraction ([`WorkerCommand`]):
//!
//! 1. [`WorkerCommand::Claude`] — the real path. Assembles a **direct `bwrap`**
//!    invocation (we drive `bubblewrap` ourselves rather than delegating to the
//!    `claude-sandbox` wrapper, which is a poor abstraction for programmatic
//!    use): `bwrap <base mounts> <per-role mount matrix> -- nix-shell
//!    <workspace>/shell.nix --run <claude …>`. The base mounts replicate the
//!    essential subset of `claude-sandbox`'s bwrap policy needed to run
//!    `claude` inside the project dev shell; the per-role [`MountMatrix`] is
//!    rendered into **real** `--bind` / `--ro-bind` flags (REQ-5/6/7), so the
//!    mount differentiation is now *enforced by the kernel*, not merely
//!    documented. The inner `claude` command is headless (`-p`/`--print` with a
//!    bootstrap prompt — a pane has no stdin, so without this the worker never
//!    starts), `--permission-mode default` (never
//!    `--dangerously-skip-permissions`, REQ-4), the per-role `--allowed-tools`
//!    allowlist, a `--disallowed-tools` deny list for the known-dangerous VCS
//!    verbs, the role system prompt, and `--max-turns` (REQ-4, REQ-13). These
//!    are defense-in-depth guardrails, **not** a hard cage — the honest security
//!    model lives in [`crate::roles`]. Before any such spawn the store-path pin
//!    guard (REQ-4a /
//!    AC-19) resolves `bwrap` on PATH and refuses unless it is the exact pinned
//!    nix store path. This path is *not* exercised against a live Anthropic API
//!    in tests — its argv assembly is proved by pure unit tests, and the
//!    kernel-level isolation the mount matrix produces is proved by nested-bwrap
//!    integration tests.
//! 2. [`WorkerCommand::Direct`] — run an arbitrary argv (e.g.
//!    `bash tests/fixtures/fake-implementer.sh`) directly in the prepared
//!    workspace. This is the AC-11a tracer-bullet dogfood path the build pump
//!    (#15) dispatches: no live `claude`, no nested sandbox, no pin required.
//!    It is still hosted+observable in a zellij pane exactly like a real
//!    worker. This path is **unchanged** by the direct-bwrap rework.
//!
//! # The per-role mount matrix is ENFORCED (REQ-5/6/7)
//!
//! Because the [`WorkerCommand::Claude`] arm now invokes `bwrap` directly, the
//! per-role RO/RW differentiation in [`MountMatrix`] is emitted as real bwrap
//! `--bind` / `--ro-bind` flags and enforced by the kernel's mount namespace:
//! the Adversary's namespace has **no** *repository* `.jj/` or `.git/` bind
//! (REQ-5, REQ-5a), no role gets `.orchestrator/` (REQ-6), every role gets the
//! workspace RW and `.crosslink/` RO (REQ-7). A worker literally cannot
//! `open()` a path that was never bound into its namespace.
//!
//! ## REQ-5 MECHANISM AMENDMENT — colocated repos require `.git/` (finding #1)
//!
//! REQ-5's original wording was "never mount `.git/` into any worker sandbox".
//! That is **incompatible with a jj-git-colocated repository** — which is what
//! this repo and the fixtures (created via `jj git init`) are. In a colocated
//! repo `.jj/repo/store` points at `<root>/.git` as its object backend: jj
//! *inside* the namespace follows that pointer and, if `<root>/.git` is not
//! mounted, dies with `"…/.git does not appear to be a git repository"`. The
//! Implementer/Merger sandbox would be **non-functional** — it could not so
//! much as run `jj status`.
//!
//! RESOLUTION: the roles that need `.jj/` (Implementer, Merger) also get
//! `<root>/.git` bound **RW** — jj must write objects to the colocated backend.
//! This means the mount matrix no longer withholds the VCS store from the
//! committing roles. The tool allowlist + deny list narrow what the worker is
//! *nudged* to do, but they are **not** a hard boundary: `Bash(cargo …)` runs
//! arbitrary compiled code and `Write`/`Edit` can touch the RW `.jj/`/`.git/`,
//! so a determined worker is not caged by any jj-verb allowlist. The real
//! protection for `main` is **orchestrator-side validation** (the QA gate, the
//! FF-guarded landing that can only advance trunk, and adversary review) — see
//! the threat-model block in [`crate::roles`]. The kernel still hides `.git/`
//! from the roles that have no `.jj/` (Adversary, Judge). See
//! [`MountMatrix::for_role`].
//!
//! ## The Adversary's own workspace `.jj/` (finding #3, honest statement)
//!
//! A worker's jj *workspace* directory carries its **own** working-copy
//! metadata at `<workspace>/.jj` (distinct from the shared *repository* `.jj/`
//! at `<root>`). Because every role gets the workspace bound RW, the Adversary's
//! namespace *does* contain `<workspace>/.jj` — it lacks only the **repository**
//! `<root>/.jj` and `<root>/.git`. The working-copy `.jj` is inert without the
//! repo store, so this is acceptable for the MVP (the Adversary is an
//! iteration-2 role). FOLLOW-UP: the Adversary should be given a *plain-files*
//! workspace (a rendered diff, not a jj workspace) so it carries no `.jj` at
//! all — tracked, not built here.
//!
//! # Invariants made unrepresentable
//!
//! - **No stringly-typed spawn.** The role is [`WorkerRole`], the pane name is
//!   built from the typed spawn coordinates, and [`WorkerCommand`] is a closed
//!   enum — never a free-form command string.
//! - **The mount matrix is a total function of the role.** [`MountMatrix`] is
//!   built only by [`MountMatrix::for_role`]; there is no public field-setter,
//!   so an illegal per-role mount set (an Adversary with `.jj/`) cannot be
//!   *described* — and, now, cannot be *emitted*: [`MountMatrix::render`] is
//!   the only path from the matrix to bwrap flags.
//! - **A pin-unchecked real spawn is impossible.** The store-path pin guard
//!   runs *inside* [`Spawner::spawn`] on the [`WorkerCommand::Claude`] arm,
//!   before the pane is created. A caller cannot opt out — there is no "spawn
//!   without guard" entry point.
//! - **Workers never inherit orchestrator secrets.** Every worker's pane
//!   command is built with a cleared environment plus a minimal allowlist
//!   ([`WORKER_ENV_ALLOWLIST`]); the orchestrator's API keys, tokens, and the
//!   pin itself are scrubbed before the worker starts (REQ env-hygiene).
//!
//! # No shell-out (AC-24)
//!
//! zellij is reached only through [`vetinari_zellij_host`]. `bwrap`,
//! `nix-shell`, and `claude` are whitelisted `Command`/argv targets (the
//! orchestrator never drives `jj`/`git`/`gh`/`crosslink`/`zellij` as
//! subprocesses); the pin guard's PATH resolution of `bwrap` goes through the
//! standard library, not a subprocess. The worker argv itself is handed to
//! zellij, which execs it — the orchestrator constructs no `Command` here.

// SpawnError carries rich miette diagnostic context (a boxed jj_api source, a
// captured PATH, conflict-file lists), pushing it over clippy's large-`Err`
// threshold — same rationale as the `error` crate's own crate-level allow.
// Spawn failures propagate at human-decision rate (a spawn is a heavyweight
// operation), never in a hot loop, so the variant size is the wrong axis to
// optimize.
#![allow(clippy::result_large_err)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use vetinari_error::SpawnError;
use vetinari_zellij_host::{pane_alive, pane_close, PaneHandle, SessionHandle};

use crate::state::WorkerRole;
use crate::workspace::PreparedWorkspace;

/// The `bwrap` (bubblewrap) binary — the isolation boundary the orchestrator
/// drives **directly** to enforce the per-role mount matrix (REQ-5/6/7). One of
/// the whitelisted external targets (AC-24): it has no Rust library form, and
/// the no-shell-out lint bans only `jj`/`git`/`gh`/`crosslink`/`zellij`.
pub const BWRAP_BIN: &str = "bwrap";

/// The `nix-shell` binary — enters the project's pinned dev shell so `claude`
/// runs with the exact toolchain the workspace expects (mirrors how
/// `claude-sandbox` re-enters the dev shell before launching its command).
pub const NIX_SHELL_BIN: &str = "nix-shell";

/// The dev-shell entry file resolved inside the worker's workspace. The worker
/// enters `<workspace>/shell.nix` — the jj workspace materializes the full repo
/// tree, so the dev shell definition is present at the workspace root.
pub const SHELL_NIX_FILE: &str = "shell.nix";

/// The `claude` CLI — the whitelisted worker entrypoint (AC-24), launched
/// inside the dev shell.
pub const CLAUDE_BIN: &str = "claude";

/// The `.jj/` repository directory a worker's sandbox may see (REQ-5), relative
/// to the repository root.
pub const JJ_DIR: &str = ".jj";

/// The `.crosslink/` directory workers get a read-only bind of (REQ-7).
pub const CROSSLINK_DIR: &str = ".crosslink";

/// The `.git/` directory the colocated jj backend lives in. Bound **RW** for
/// the roles that get `.jj/` (Implementer, Merger) — jj follows
/// `.jj/repo/store` to `<root>/.git` and must write objects there (REQ-5
/// mechanism amendment, finding #1). Never bound for the Adversary or Judge.
pub const GIT_DIR: &str = ".git";

/// The `.orchestrator/` directory that is **never** bound into any worker
/// sandbox (REQ-6). Named for the same greppability reason as [`GIT_DIR`].
pub const ORCHESTRATOR_DIR: &str = ".orchestrator";

/// The env var the dev shell captures the resolved `bwrap` nix store path into
/// (REQ-4a). The store path uniquely identifies the pinned bubblewrap build;
/// the pin guard refuses to spawn unless the `bwrap` on PATH resolves to it.
/// Set by `shell.nix`'s `shellHook`.
pub const BWRAP_PIN_ENV: &str = "VDD_BWRAP_PIN";

/// The env var the dev shell captures the resolved `nix-shell` store path into.
/// Used to invoke the dev shell by its exact pinned path (like `claude-sandbox`
/// hardcodes `NIX_SHELL`); if unset, [`SandboxHost::resolve`] falls back to the
/// `nix-shell` on PATH. Set by `shell.nix`'s `shellHook`.
///
/// **Why this pin is used but NOT store-path-verified like [`BWRAP_PIN_ENV`]
/// (finding #5).** `bwrap` *establishes* the isolation namespace, so it is the
/// security boundary and must be pinned + verified (an attacker-substituted
/// `bwrap` on PATH would defeat the whole matrix — hence [`SandboxPin::verify`]
/// fails closed). `nix-shell`, by contrast, executes **inside** the namespace
/// `bwrap` has already established (after the `--` separator), so a drifted
/// `nix-shell` cannot escape the mounts, drop a mount, or reach a path the
/// matrix withheld. It is therefore a *convenience launcher pin* — used as the
/// exact path when present so the dev shell resolves identically across runs —
/// not an isolation boundary, and re-verifying its store-path would add
/// ceremony without closing an attack. Fail-closed pinning stays where the
/// trust actually sits: `bwrap`.
pub const NIX_SHELL_PIN_ENV: &str = "VDD_NIX_SHELL_PIN";

/// The task-input artifact written into the worker's workspace before a real
/// spawn (REQ-8). The worker's role prompt instructs it to read this file first;
/// this is how the per-round task reaches a fresh-context `claude` (panes have
/// no stdin, so there is no "task on stdin" — the file is the channel).
pub const TASK_FILE: &str = "_orchestrator/task.md";

/// Fixed instruction appended to every role system prompt so the worker knows
/// its task lives in [`TASK_FILE`] (REQ-8 fresh-context delivery). Kept separate
/// from the caller-supplied role prompt so the "read your task file" contract is
/// invariant across roles and cannot be forgotten at a call site.
const TASK_PROMPT_SUFFIX: &str = "Your task for this session is written to `_orchestrator/task.md` at the root of your working directory. Read that file first; it is the sole source of your instructions for this round.";

/// The `-p`/`--print` bootstrap prompt that starts a **headless** `claude`
/// worker (REQ-8). Without an initial prompt in print mode `claude` launches an
/// interactive REPL and blocks on stdin — but a zellij pane has no stdin, so the
/// worker would hang forever. Passing this as the positional prompt under `-p`
/// makes `claude` run non-interactively from here and exit when the turn budget
/// or the task completes. The prompt is deliberately a thin pointer at the task
/// file; the actual per-round instructions live in [`TASK_FILE`], not here.
pub const HEADLESS_BOOTSTRAP: &str = "Read _orchestrator/task.md and complete the task described there, then write _orchestrator/result.md and _orchestrator/DONE as instructed.";

/// The minimal set of environment variable *names* a worker is allowed to
/// inherit from the orchestrator's ambient environment. Everything else — API
/// keys, tokens, `GH_TOKEN`, the [`BWRAP_PIN_ENV`] pin, `CROSSBRIDGE_*`
/// secrets — is scrubbed before the worker starts (env hygiene). A worker only
/// needs enough to find its interpreter (`PATH`), resolve `$HOME`-relative
/// config, and render a terminal (`TERM`); anything role-specific is passed
/// explicitly via the command kind's `env` list.
///
/// # `CLAUDE_CONFIG_DIR` is NOT here — it is scoped to the `Claude` command (AC-11b)
///
/// `CLAUDE_CONFIG_DIR` is deliberately **absent** from this list. It is an
/// accept-trust auth passthrough that only a live `claude` worker needs, so it
/// must never leak to a [`WorkerCommand::Direct`] (fake-worker / AC-11a)
/// dogfood. Instead of forwarding the ambient value indiscriminately, the
/// `Claude` arm of [`Spawner::spawn`] injects the **resolved** config dir
/// ([`SandboxHost::forwarded_config_dir`]) as a per-command extra env — so the
/// forwarded path is always the one actually exposed into the sandbox
/// ([`SandboxHost::base_mounts`] overlays it), never an ambient value that might
/// aim at an unbound dir (finding #2). A Direct worker gets only the allowlist
/// below plus its own explicit env, and never the operator's Claude auth.
///
/// The scrub is realized by launching the worker under `env -i <ALLOWED=…>`
/// (see [`scrub_env_prefix`]): `env -i` clears the inherited environment (the
/// equivalent of [`std::process::Command::env_clear`] for a command we hand to
/// zellij rather than spawn directly), then re-sets only these names plus any
/// caller-supplied extra env.
pub const WORKER_ENV_ALLOWLIST: &[&str] = &["PATH", "HOME", "TERM"];

/// The env var naming the `claude` config/credentials directory. Read from the
/// orchestrator's environment to derive the sandbox's config-dir exposure and
/// re-forwarded to a live `claude` worker (never to a `Direct` worker) — see
/// [`WORKER_ENV_ALLOWLIST`] and [`SandboxHost::resolve`].
pub const CLAUDE_CONFIG_DIR_ENV: &str = "CLAUDE_CONFIG_DIR";

// ============================================================================
// PaneName — a validated `<role>-<issue>-r<round>` pane name (REQ-1d)
// ============================================================================

/// A validated zellij pane name of the form `<role>-<issue>-r<round>` (REQ-1d),
/// e.g. `implementer-42-r0`.
///
/// A newtype, never a bare `String`: built only from typed spawn coordinates
/// ([`PaneName::new`]), so the pane name a worker is hosted under is always
/// well-formed and derivable from `(role, issue, round)`. The issue id is
/// sanitized to `[a-z0-9-]` so the rendered name is a single findable token
/// with no whitespace zellij would mangle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneName {
    role: WorkerRole,
    issue: String,
    round: u32,
}

impl PaneName {
    /// Build the pane name for a `role`/`issue_id`/`round` spawn. Total over any
    /// input: an `issue_id` that sanitizes to empty (all punctuation) folds to
    /// the `issue` sentinel so the rendered name is never `<role>--r<round>`.
    pub fn new(role: WorkerRole, issue_id: &str, round: u32) -> Self {
        let issue = sanitize(issue_id);
        PaneName {
            role,
            issue: if issue.is_empty() {
                "issue".to_owned()
            } else {
                issue
            },
            round,
        }
    }

    /// The rendered `<role>-<issue>-r<round>` name.
    pub fn as_str(&self) -> String {
        format!("{}-{}-r{}", self.role.as_str(), self.issue, self.round)
    }
}

impl std::fmt::Display for PaneName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// Fold an arbitrary id to `[a-z0-9-]`: lowercase alphanumerics pass through,
/// everything else becomes `-`, runs of `-` collapse, leading/trailing `-`
/// trimmed. Mirrors `workspace.rs`'s sanitizer so a pane name and its
/// workspace name agree on the issue token.
fn sanitize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_owned()
}

// ============================================================================
// MountMatrix — the per-role bind surface (REQ-5, REQ-6, REQ-7)
// ============================================================================

/// Access mode for a bind mount into a worker sandbox. Emitted as a real bwrap
/// flag by [`Mount::flag`] — enforced by the kernel's mount namespace, not
/// merely documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountMode {
    /// Read-write bind (bwrap `--bind`).
    ReadWrite,
    /// Read-only bind (bwrap `--ro-bind`).
    ReadOnly,
}

/// One bind mount: a host path bound to the same path inside the sandbox, at a
/// given [`MountMode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Host path being bound (absolute).
    pub source: PathBuf,
    /// Access mode inside the sandbox.
    pub mode: MountMode,
}

impl Mount {
    /// The bwrap flag for this mount's mode: `--bind` (RW) or `--ro-bind` (RO).
    pub fn flag(&self) -> &'static str {
        match self.mode {
            MountMode::ReadWrite => "--bind",
            MountMode::ReadOnly => "--ro-bind",
        }
    }

    /// Render this mount as the three bwrap argv tokens
    /// `[<flag>, <source>, <source>]` — bound to the **same** path inside the
    /// sandbox as on the host (so a worker's absolute paths are unchanged).
    fn render_into(&self, out: &mut Vec<String>) {
        let src = self.source.to_string_lossy().into_owned();
        out.push(self.flag().to_owned());
        out.push(src.clone());
        out.push(src);
    }
}

/// The per-role bind surface a worker sandbox *should* be given (the design's
/// mount table, REQ-5/6/7). Built *only* by [`MountMatrix::for_role`]: there is
/// no public field-setter and no other constructor, so an illegal per-role
/// mount set is unrepresentable — an [`WorkerRole::Adversary`] can never carry
/// the repository `.jj/` or `.git/`, and `.orchestrator/` is never present for
/// *any* role because no code path adds it.
///
/// The repository `.jj/` and `.git/` always travel **together** (the REQ-5
/// mechanism amendment, finding #1): a colocated repo's jj backend lives in
/// `<root>/.git`, so a role that gets `.jj/` must also get `.git/` or jj cannot
/// open the repo. Both go to the Implementer and Merger; neither to the
/// Adversary or Judge.
///
/// This surface is **enforced**, not merely intended: [`MountMatrix::render`]
/// emits it as real bwrap `--bind` / `--ro-bind` flags on the
/// [`WorkerCommand::Claude`] spawn path, so the kernel's mount namespace is
/// what actually denies an Adversary access to the repository `.jj/`/`.git/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountMatrix {
    mounts: Vec<Mount>,
}

impl MountMatrix {
    /// Derive the mount surface for `role`, given the repository `root` and the
    /// worker's prepared `workspace` directory. A total function of the role:
    ///
    /// | Mount                | Implementer | Adversary | Merger | Judge |
    /// |----------------------|-------------|-----------|--------|-------|
    /// | workspace dir (RW)   | yes         | yes       | yes    | yes   |
    /// | `<root>/.jj/` (RW)   | yes         | **no**    | yes    | no    |
    /// | `<root>/.git/` (RW)  | yes         | **no**    | yes    | no    |
    /// | `<root>/.crosslink/` (RO) | yes    | yes       | yes    | yes   |
    /// | `<root>/.orchestrator/` | **no**   | **no**    | **no** | **no**|
    ///
    /// The Implementer and Merger see the repository `.jj/` **and** `.git/`, both
    /// RW (they commit via the `jj` CLI, and the colocated jj backend writes
    /// objects into `<root>/.git` — REQ-5 mechanism amendment, finding #1); the
    /// Adversary/Judge get neither (the Adversary only reads a pre-rendered diff,
    /// REQ-8, and its concurrency budget assumes no repo `.jj/` mount, REQ-5a).
    /// Every role gets the workspace RW and `.crosslink/` RO (REQ-7).
    /// `.orchestrator/` (REQ-6) is physically absent for all roles — no branch
    /// here binds it.
    ///
    /// **Isolation shift (finding #1):** with `.git/` now granted RW to the
    /// committing roles, the mount matrix no longer withholds the VCS store from
    /// them. The S7 tool allowlist + deny list are defense-in-depth guardrails
    /// (they make the intended `jj` path the easy one), **not** a hard cage: a
    /// worker running `Bash(cargo …)` or `Write`/`Edit` against the RW
    /// `.jj/`/`.git/` is not contained by any jj-verb allowlist. What actually
    /// keeps a bad change off `main` is orchestrator-side validation before
    /// landing — see the threat-model block in [`crate::roles`].
    ///
    /// **The Adversary's workspace still carries its own `<workspace>/.jj`
    /// (finding #3):** the workspace RW bind includes the jj *workspace's*
    /// working-copy metadata. What the matrix withholds from the Adversary is the
    /// *repository* `<root>/.jj` and `<root>/.git`, not the inert working-copy
    /// `.jj` under the workspace. A plain-files Adversary workspace is a
    /// documented follow-up.
    ///
    /// **REQ-7 dependency (doc note):** the RW `.jj/` grant is only *safe*
    /// because concurrent writers to the shared `.jj/` are serialized by the
    /// orchestrator-side external allowlist + per-repo mutex (S2). Two workers
    /// mutating `.jj/` at once would corrupt the operation log; this matrix
    /// grants the mount but the S2 mutex is what makes granting it sound. Now
    /// that the grant is really enforced (rendered as a bwrap `--bind`), this
    /// safety dependency is live, not hypothetical: if S2 ever stops serializing
    /// `.jj/` writers, this RW grant becomes unsafe.
    pub fn for_role(role: WorkerRole, root: &Path, workspace: &Path) -> Self {
        let mut mounts = vec![
            // The workspace working copy: read-write for every role.
            Mount {
                source: workspace.to_path_buf(),
                mode: MountMode::ReadWrite,
            },
            // `.crosslink/`: read-only for every role (REQ-7).
            Mount {
                source: root.join(CROSSLINK_DIR),
                mode: MountMode::ReadOnly,
            },
        ];
        // `.jj/` + `.git/` RW for the roles that commit; never for the Adversary
        // or the (MVP-stub) Judge. This is the one role-conditional branch, and
        // the *only* place the repository `.jj/`/`.git/` is ever added. They are
        // bound together because a colocated repo's jj backend lives in
        // `<root>/.git`: jj follows `.jj/repo/store` there and fails if it is
        // absent (REQ-5 mechanism amendment, finding #1).
        if role_gets_jj(role) {
            mounts.push(Mount {
                source: root.join(JJ_DIR),
                mode: MountMode::ReadWrite,
            });
            mounts.push(Mount {
                source: root.join(GIT_DIR),
                mode: MountMode::ReadWrite,
            });
        }
        // NOTE: `.orchestrator/` (REQ-6) is deliberately NOT added by any
        // branch; its absence is the invariant. `.git/` is absent only for the
        // non-committing roles (Adversary/Judge) — see the branch above.
        MountMatrix { mounts }
    }

    /// The mounts in a stable order (workspace, `.crosslink/`, then `.jj/` if
    /// present).
    pub fn mounts(&self) -> &[Mount] {
        &self.mounts
    }

    /// Whether this matrix binds the repository `.jj/` (true for
    /// Implementer/Merger only).
    pub fn has_jj(&self) -> bool {
        self.mounts
            .iter()
            .any(|m| m.source.file_name().is_some_and(|n| n == JJ_DIR))
    }

    /// Whether this matrix binds the colocated `.git/` backend (true for
    /// Implementer/Merger only — it always travels with `.jj/`, finding #1).
    pub fn has_git(&self) -> bool {
        self.mounts
            .iter()
            .any(|m| m.source.file_name().is_some_and(|n| n == GIT_DIR))
    }

    /// Render the whole per-role surface into bwrap argv tokens — a flat
    /// `[--bind, src, src, --ro-bind, src, src, …]` in [`mounts`] order
    /// (workspace RW, `.crosslink/` RO, then `.jj/` RW if present). This is the
    /// **only** path from the matrix to bwrap flags: what `for_role` refuses to
    /// build, `render` cannot emit, so the Adversary's argv can never carry a
    /// `.jj/` bind.
    ///
    /// [`mounts`]: MountMatrix::mounts
    pub fn render(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.mounts.len() * 3);
        for mount in &self.mounts {
            mount.render_into(&mut out);
        }
        out
    }
}

/// Build the `env -i KEY=VALUE …` prefix that scrubs the orchestrator's
/// ambient environment down to a minimal allowlist before the worker runs.
///
/// The worker command is handed to zellij, which spawns it inheriting the
/// zellij server's environment (the orchestrator's full ambient env — API
/// keys, tokens, the [`BWRAP_PIN_ENV`] pin). We cannot call
/// [`std::process::Command::env_clear`] on that spawn because *we* don't spawn
/// it; instead we prepend `env -i`, whose effect is identical — it discards the
/// inherited environment — and then re-set only:
///
/// - the [`WORKER_ENV_ALLOWLIST`] names, read from *our* environment (a worker
///   still needs `PATH` to find its interpreter, `HOME` for config, `TERM` for
///   a terminal), and
/// - any `extra` env the caller explicitly attached to a
///   [`WorkerCommand::Direct`].
///
/// The returned vector is `["env", "-i", "K=V", …]`, to be prepended to the
/// worker's own argv. An allowlisted name that is unset in our environment is
/// simply omitted (nothing to forward).
///
/// `pub(crate)` so the static QA gate ([`crate::qa`]) reuses the exact same
/// env-scrub the worker spawn path uses — the QA child is wrapped in the same
/// `env -i <allowlist>` prefix, so `GH_TOKEN`/the pin/API keys never reach
/// worker-authored `build.rs`/test code under grading. The logic lives here and
/// is shared, never duplicated.
pub(crate) fn scrub_env_prefix(extra: &[(String, String)]) -> Vec<String> {
    let mut prefix = vec!["env".to_owned(), "-i".to_owned()];
    for &name in WORKER_ENV_ALLOWLIST {
        if let Ok(value) = std::env::var(name) {
            prefix.push(format!("{name}={value}"));
        }
    }
    for (key, value) in extra {
        prefix.push(format!("{key}={value}"));
    }
    prefix
}

/// Whether `role` gets a `.jj/` bind. The single decision point for the
/// role→`.jj/` rule (REQ-5): Implementer and Merger commit through `jj`, so
/// they see `.jj/`; the Adversary reads a pre-rendered diff and the Judge is an
/// MVP stub, so neither does.
fn role_gets_jj(role: WorkerRole) -> bool {
    matches!(role, WorkerRole::Implementer | WorkerRole::Merger)
}

/// Resolve the `claude` config-dir exposure + the `CLAUDE_CONFIG_DIR` to forward
/// to a live worker, from the orchestrator's environment (AC-11b, findings
/// #2/#3). Returns `(forwarded, overlays)`:
///
/// - `overlays` — the config dirs to expose **write-discarding** into the
///   sandbox ([`SandboxHost::config_overlays`]). Only dirs that exist on disk.
/// - `forwarded` — the `CLAUDE_CONFIG_DIR` value a live `claude` worker gets,
///   or `None` to let `claude` use its own default resolution.
///
/// Fails closed with [`SpawnError::ClaudeConfigMissing`] when
/// `CLAUDE_CONFIG_DIR` is set but names a directory that does not exist: rather
/// than forward a var aimed at an unbound dir (which would 401 the worker), the
/// spawn is refused so the misconfiguration surfaces as a typed error.
///
/// When `CLAUDE_CONFIG_DIR` is set (and valid) it is the primary overlaid dir
/// AND the forwarded value, keeping the two coupled. The legacy `~/.claude` is
/// additionally overlaid when it exists (claude reads it for plugins, etc.).
/// When unset, the default `~/.config/claude` + `~/.claude` are overlaid if
/// present and nothing is forwarded — exactly the prior default behavior, now
/// write-discarding.
fn resolve_claude_config(home: &Path) -> Result<(Option<PathBuf>, Vec<PathBuf>), SpawnError> {
    let mut overlays: Vec<PathBuf> = Vec::new();
    let forwarded = match std::env::var_os(CLAUDE_CONFIG_DIR_ENV) {
        Some(v) if !v.is_empty() => {
            let dir = PathBuf::from(v);
            if !dir.is_dir() {
                // Fail closed: a set-but-absent CLAUDE_CONFIG_DIR must not ship a
                // sandbox whose forwarded var aims at an unbound dir (finding #2).
                return Err(SpawnError::ClaudeConfigMissing { path: dir });
            }
            overlays.push(dir.clone());
            Some(dir)
        }
        _ => {
            // Default resolution: expose the default config dir if it exists.
            let default = home.join(".config/claude");
            if default.is_dir() {
                overlays.push(default);
            }
            None
        }
    };
    // The legacy `~/.claude` is overlaid too when present (unless it is already
    // the forwarded dir).
    let legacy = home.join(".claude");
    if legacy.is_dir() && !overlays.contains(&legacy) {
        overlays.push(legacy);
    }
    Ok((forwarded, overlays))
}

// ============================================================================
// WorkerCommand — the two spawn kinds
// ============================================================================

/// The two kinds of worker the spawn layer can host, behind one abstraction.
///
/// A closed enum, never a free-form command string: the caller picks a variant,
/// and [`Spawner::spawn`] hosts it in a pane. The real ([`Claude`]) arm runs
/// the version-pin guard first; the direct arm does not (it is the dogfood
/// path).
///
/// [`Claude`]: WorkerCommand::Claude
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerCommand {
    /// Run an arbitrary argv directly in the prepared workspace (the fake-worker
    /// / AC-11a dogfood path). No `bwrap`, no nested sandbox, no pin check. Still
    /// hosted in a zellij pane so it is observable like a real worker.
    Direct {
        /// The program plus its arguments (must be non-empty). The pane runs
        /// this verbatim in the workspace cwd.
        argv: Vec<String>,
        /// Extra environment applied to the pane (zellij prefixes `env K=V …`).
        env: Vec<(String, String)>,
    },
    /// Spawn a real `claude` worker inside a direct `bwrap` sandbox with the
    /// per-role mount matrix enforced, allowlist, prompt, and turn cap (REQ-4,
    /// REQ-5, REQ-13). The `bwrap` store-path pin guard (REQ-4a) runs before
    /// this is launched.
    Claude(ClaudeSpawn),
}

/// The fully-specified inputs of a real `claude` spawn. Held in its own struct
/// so [`ClaudeSpawn::to_argv`] can be a pure, unit-testable function of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeSpawn {
    /// The worker role (drives the allowlist, prompt, and — via
    /// [`MountMatrix::for_role`] — the mount surface).
    pub role: WorkerRole,
    /// The task prompt for this round (REQ-8). Delivered by writing it to
    /// [`TASK_FILE`] (`_orchestrator/task.md`) in the worker's workspace before
    /// the pane is created; the role system prompt tells the worker to read that
    /// file. Panes have no stdin, so the file — not stdin — is the channel.
    pub task: String,
    /// The per-role `--allowed-tools` value (REQ-4, REQ-5). A closed string the
    /// caller derives from the role's allowlist.
    pub allowlist: String,
    /// The per-role `--disallowed-tools` value: a belt-and-suspenders deny list
    /// of the known-dangerous VCS verbs (git, push/fetch, history/op-log
    /// surgery). Unlike the allowlist — where an *unlisted* tool under
    /// `--permission-mode default` merely ASKS and, headless, wedges the worker
    /// until the pump's timeout — an explicitly denied tool is refused outright
    /// with no prompt. Empty for roles that need no extra deny. This is
    /// defense-in-depth, **not** a hard cage (see [`crate::roles`]).
    pub denylist: String,
    /// The role system prompt, passed via `--append-system-prompt`.
    pub system_prompt: String,
    /// The per-role `--max-turns` cap (REQ-13).
    pub max_turns: u32,
    /// The per-role bind surface.
    pub mounts: MountMatrix,
}

impl WorkerCommand {
    /// Build a [`WorkerCommand::Direct`] from an argv and env. Convenience so
    /// callers don't spell the struct.
    pub fn direct(
        argv: impl IntoIterator<Item = impl Into<String>>,
        env: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        WorkerCommand::Direct {
            argv: argv.into_iter().map(Into::into).collect(),
            env: env.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
        }
    }

    /// Build a [`WorkerCommand::Claude`] for `role`, deriving the mount matrix
    /// from the role and the prepared `workspace` under `root`.
    #[allow(clippy::too_many_arguments)]
    pub fn claude(
        role: WorkerRole,
        root: &Path,
        workspace: &Path,
        task: impl Into<String>,
        allowlist: impl Into<String>,
        denylist: impl Into<String>,
        system_prompt: impl Into<String>,
        max_turns: u32,
    ) -> Self {
        WorkerCommand::Claude(ClaudeSpawn {
            role,
            task: task.into(),
            allowlist: allowlist.into(),
            denylist: denylist.into(),
            system_prompt: system_prompt.into(),
            max_turns,
            mounts: MountMatrix::for_role(role, root, workspace),
        })
    }
}

impl ClaudeSpawn {
    /// The literal `claude` command tokens run *inside* the dev shell (REQ-4,
    /// REQ-13), as an inspectable argv:
    ///
    /// ```text
    /// claude -p '<bootstrap>' \
    ///        --permission-mode default \
    ///        --allowed-tools <allowlist> \
    ///        --disallowed-tools <denylist> \
    ///        --append-system-prompt <prompt> \
    ///        --max-turns <n>
    /// ```
    ///
    /// **`-p`/`--print` is what makes the worker actually start.** Panes have no
    /// stdin, and bare `claude` opens an interactive REPL that would block
    /// forever waiting for input. `-p` with the positional [`HEADLESS_BOOTSTRAP`]
    /// prompt runs `claude` non-interactively and lets it exit when the task or
    /// the turn budget completes. The bootstrap only points the worker at its
    /// task file; the per-round instructions are delivered as a file
    /// ([`TASK_FILE`], REQ-8), and the system prompt carries a fixed instruction
    /// ([`TASK_PROMPT_SUFFIX`]) to read it — the task text is never on argv.
    ///
    /// `--permission-mode default` and the *absence* of
    /// `--dangerously-skip-permissions` are hard-coded (REQ-4): there is no
    /// argument that could turn them off. Note that `default` mode **ASKS** for
    /// an unlisted tool rather than cleanly denying it — headless, such a prompt
    /// has no one to answer it and wedges the worker until the pump's
    /// `worker_timeout` treats the stall as a crash. The `--disallowed-tools`
    /// deny list ([`ClaudeSpawn::denylist`]) is therefore the *clean* refusal
    /// path for the known-dangerous VCS verbs; it is emitted only when non-empty.
    ///
    /// This is the unit under test for the REQ-4/REQ-13 flag contract;
    /// [`to_argv`](Self::to_argv) shell-joins it into the `nix-shell --run`
    /// string.
    pub fn claude_argv(&self) -> Vec<String> {
        let mut argv = vec![
            CLAUDE_BIN.to_owned(),
            // Headless: run non-interactively from the bootstrap prompt and exit
            // (a pane has no stdin for an interactive REPL to read).
            "-p".to_owned(),
            HEADLESS_BOOTSTRAP.to_owned(),
            "--permission-mode".to_owned(),
            "default".to_owned(),
            "--allowed-tools".to_owned(),
            self.allowlist.clone(),
        ];
        // Belt-and-suspenders: cleanly deny the known-dangerous VCS verbs so
        // they are refused outright rather than triggering a (headless-hanging)
        // permission prompt. Emitted only when a deny list is configured.
        if !self.denylist.is_empty() {
            argv.push("--disallowed-tools".to_owned());
            argv.push(self.denylist.clone());
        }
        argv.push("--append-system-prompt".to_owned());
        argv.push(format!("{}\n\n{}", self.system_prompt, TASK_PROMPT_SUFFIX));
        argv.push("--max-turns".to_owned());
        argv.push(self.max_turns.to_string());
        argv
    }

    /// Assemble the full **direct `bwrap`** argv as a pure function of the spawn
    /// inputs, the `workspace`, and the resolved [`SandboxHost`] — nothing is
    /// spawned, so this is unit-testable in isolation (the live-claude path is
    /// never exercised in tests, so its correctness is proved *here* and by the
    /// nested-bwrap isolation tests).
    ///
    /// The shape:
    ///
    /// ```text
    /// bwrap <base mounts> \
    ///       <per-role mount matrix as --bind/--ro-bind> \
    ///   -- nix-shell <workspace>/shell.nix \
    ///        --run 'claude --permission-mode default …'
    /// ```
    ///
    /// The per-role [`MountMatrix`] is rendered into **real** `--bind` /
    /// `--ro-bind` flags ([`MountMatrix::render`]) — so REQ-5/6/7 are enforced
    /// by the kernel's mount namespace, not just documented. The base mounts
    /// ([`SandboxHost::base_mounts`]) replicate the essential subset of
    /// `claude-sandbox`'s bwrap policy needed to run `claude` in the dev shell.
    /// The inner `claude` command ([`claude_argv`](Self::claude_argv)) is
    /// POSIX-shell-quoted into the single `nix-shell --run` string.
    pub fn to_argv(&self, workspace: &Path, host: &SandboxHost) -> Vec<String> {
        let mut argv = self.bwrap_prefix(workspace, host);
        // Enter the dev shell and launch claude.
        argv.push("--".to_owned());
        argv.push(host.nix_shell.to_string_lossy().into_owned());
        argv.push(
            workspace
                .join(SHELL_NIX_FILE)
                .to_string_lossy()
                .into_owned(),
        );
        argv.push("--run".to_owned());
        argv.push(shell_join(&self.claude_argv()));
        argv
    }

    /// The bwrap argv **up to (but excluding) the `--` separator**: the pinned
    /// `bwrap` binary, the base sandbox policy ([`SandboxHost::base_mounts`]),
    /// and the per-role matrix ([`MountMatrix::render`]). This is the exact
    /// namespace assembly [`to_argv`](Self::to_argv) uses; it is factored out so
    /// the live nested-bwrap isolation tests can drive the **real** base-mounts
    /// and matrix rendering (appending their own `-- <probe>` tail) instead of
    /// hand-building an arg vector that could drift from production (finding #4).
    pub fn bwrap_prefix(&self, workspace: &Path, host: &SandboxHost) -> Vec<String> {
        let mut argv = vec![host.bwrap.to_string_lossy().into_owned()];
        // Base sandbox policy (essential subset of claude-sandbox's mounts).
        argv.extend(host.base_mounts(workspace));
        // The per-role bind surface — REAL enforcement of REQ-5/6/7.
        argv.extend(self.mounts.render());
        argv
    }
}

/// Write the per-round task prompt to [`TASK_FILE`] inside `workspace` (REQ-8).
///
/// The worker's system prompt ([`TASK_PROMPT_SUFFIX`]) tells it to read this
/// file first. Creates the `_orchestrator/` parent if needed. Any I/O failure
/// surfaces as a typed [`SpawnError::Io`] carrying the offending path — a
/// garbled task delivery must be a clean error, not a silent empty prompt.
fn write_task_file(workspace: &Path, task: &str) -> Result<(), SpawnError> {
    let path = workspace.join(TASK_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SpawnError::io(parent, e))?;
    }
    std::fs::write(&path, task).map_err(|e| SpawnError::io(&path, e))
}

/// POSIX-quote one argv token for embedding in a `nix-shell --run` command
/// string. Tokens made purely of safe characters pass through bare; anything
/// else is single-quoted with embedded `'` escaped as `'\''`.
fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=,+@".contains(&b));
    if safe {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Shell-join an argv into a single command string safe for `nix-shell --run`.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

// ============================================================================
// SandboxHost — resolved host binaries + base bwrap mount policy
// ============================================================================

/// The resolved host paths a direct-`bwrap` spawn needs: the pinned isolation
/// binary, the dev-shell launcher, the host `$HOME` to shadow, `/bin/sh`'s
/// backing shell, and the *existing* host config directories to expose. Held
/// as a struct so [`ClaudeSpawn::to_argv`] stays a **pure** function of it
/// (unit tests build a fixed `SandboxHost`), while [`SandboxHost::resolve`]
/// does the environment/filesystem probing once at spawn time.
///
/// The base config binds are resolved to only the paths that actually exist:
/// an unconditional `--ro-bind` of an absent path makes `bwrap` fail, so
/// `resolve` stats each candidate and keeps the survivors.
///
/// # The claude config dir is exposed WRITE-DISCARDING (AC-11b, finding #3)
///
/// The operator's `claude` config/credentials directory is **not** bound
/// read-write. An earlier revision `--bind`-ed it RW, which let a worker
/// rewrite the operator's credentials, hooks, and MCP config — a persistence
/// vector into the operator's next interactive session. Instead each config dir
/// in [`config_overlays`] is exposed via bwrap's `--overlay-src …
/// --tmp-overlay …`: the host dir is the **read-only lower layer** (so `claude`
/// reads the real credentials and authenticates), and all writes land in an
/// **invisible tmpfs upper layer** that is discarded when the sandbox tears
/// down — the host config is never mutated. Verified empirically: a live
/// `claude -p` authenticates through the overlay, and a write into the config
/// dir inside the namespace does not appear on the host afterward.
///
/// [`config_overlays`]: SandboxHost::config_overlays
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxHost {
    /// Pinned, PATH-verified `bwrap` store path (the isolation binary).
    bwrap: PathBuf,
    /// Pinned `nix-shell` store path (enters the project dev shell).
    nix_shell: PathBuf,
    /// The shell backing `/bin/sh` inside the sandbox (programs like `claude`
    /// spawn `/bin/sh`). Symlinked, never bound.
    sh: PathBuf,
    /// Host `$HOME`, shadowed by a tmpfs so the worker gets an empty home.
    home: PathBuf,
    /// Existing host paths to expose read-only (nix profile + state, git/jj
    /// config). Only paths that exist on disk — see the type doc.
    ro_binds: Vec<PathBuf>,
    /// Existing `claude` config dirs to expose **write-discarding** (host RO
    /// lower + tmpfs upper, via `--tmp-overlay`) so the worker authenticates
    /// without being able to mutate the operator's config. Only paths that
    /// exist on disk. See the type doc (finding #3).
    config_overlays: Vec<PathBuf>,
    /// The `CLAUDE_CONFIG_DIR` value to forward to a live `claude` worker, when
    /// the orchestrator's environment set it (finding #2). `Some` only when the
    /// operator selected a non-default config dir; that dir is guaranteed to be
    /// present in [`config_overlays`], so the forwarded path always aims at an
    /// exposed dir. `None` when unset — `claude` then uses its own default
    /// resolution and no `CLAUDE_CONFIG_DIR` is forwarded.
    forwarded_config_dir: Option<PathBuf>,
}

impl SandboxHost {
    /// Build a host descriptor from explicit paths — the constructor unit tests
    /// use to get a deterministic, filesystem-independent [`SandboxHost`].
    pub fn new(
        bwrap: impl Into<PathBuf>,
        nix_shell: impl Into<PathBuf>,
        sh: impl Into<PathBuf>,
        home: impl Into<PathBuf>,
        ro_binds: Vec<PathBuf>,
        config_overlays: Vec<PathBuf>,
        forwarded_config_dir: Option<PathBuf>,
    ) -> Self {
        SandboxHost {
            bwrap: bwrap.into(),
            nix_shell: nix_shell.into(),
            sh: sh.into(),
            home: home.into(),
            ro_binds,
            config_overlays,
            forwarded_config_dir,
        }
    }

    /// The `CLAUDE_CONFIG_DIR` to forward to a live `claude` worker, if the
    /// orchestrator's environment selected a non-default config dir. Always
    /// points at a dir exposed into the sandbox (finding #2). `None` ⇒ forward
    /// nothing and let `claude` use its default resolution.
    pub fn forwarded_config_dir(&self) -> Option<&Path> {
        self.forwarded_config_dir.as_deref()
    }

    /// Resolve the host descriptor at spawn time from `pin` (the verified
    /// `bwrap` path) plus the ambient environment. `nix-shell` comes from
    /// [`NIX_SHELL_PIN_ENV`] when set, else the `nix-shell` on PATH; `$HOME`
    /// seeds the config-bind candidates, each kept only if it exists.
    ///
    /// Fails closed with [`SpawnError::BwrapMissing`] if `$HOME` is unset (the
    /// sandbox cannot be assembled without a home to shadow) or `nix-shell`
    /// cannot be located.
    pub fn resolve(pin: &SandboxPin) -> Result<Self, SpawnError> {
        let path_env = std::env::var("PATH").unwrap_or_default();
        let (home, sh, ro_binds) = Self::resolve_home_sh_ro(&path_env)?;

        let nix_shell = match std::env::var_os(NIX_SHELL_PIN_ENV) {
            Some(v) if !v.is_empty() => PathBuf::from(v),
            _ => resolve_on_path(NIX_SHELL_BIN, &path_env).ok_or_else(|| {
                SpawnError::BwrapMissing {
                    searched: format!("{NIX_SHELL_PIN_ENV} unset; {NIX_SHELL_BIN} not on PATH"),
                }
            })?,
        };

        // Derive the claude config-dir exposure + forward from CLAUDE_CONFIG_DIR
        // (finding #2/#3): the forwarded var and the overlaid dir come from the
        // same source, so a forwarded path always aims at an exposed dir.
        let (forwarded_config_dir, config_overlays) = resolve_claude_config(&home)?;

        Ok(SandboxHost {
            bwrap: PathBuf::from(pin.expected()),
            nix_shell,
            sh,
            home,
            ro_binds,
            config_overlays,
            forwarded_config_dir,
        })
    }

    /// Resolve a host descriptor for the **static QA gate only** — the subset
    /// [`qa_mounts`](SandboxHost::qa_mounts) actually consumes (`home`, `sh`,
    /// `ro_binds`) plus the `bwrap` pin, and NOTHING ELSE.
    ///
    /// [`resolve`](SandboxHost::resolve) additionally locates `nix-shell` (failing
    /// closed if it is absent) and stats the operator's `claude` config dirs to
    /// build the write-discarding creds overlay. `qa_mounts` uses *neither*: QA
    /// never enters the dev shell and deliberately drops the creds overlay (it
    /// grades worker-authored code and must not expose operator credentials to
    /// it). Requiring `nix-shell` and resolving the claude config on the QA path
    /// would be an irrelevant hard dependency — a host with a working pinned
    /// `bwrap` but no `nix-shell` on PATH would poison every issue at gate
    /// construction for a binary QA never invokes. So this constructor resolves
    /// only the QA-relevant fields; `nix_shell`/`config_overlays`/
    /// `forwarded_config_dir` are left empty because `qa_mounts` never reads them.
    pub fn resolve_for_qa(pin: &SandboxPin) -> Result<Self, SpawnError> {
        let path_env = std::env::var("PATH").unwrap_or_default();
        let (home, sh, ro_binds) = Self::resolve_home_sh_ro(&path_env)?;

        Ok(SandboxHost {
            bwrap: PathBuf::from(pin.expected()),
            // Unused by `qa_mounts` (QA never enters the dev shell). Empty rather
            // than resolved so the QA path carries no `nix-shell` dependency.
            nix_shell: PathBuf::new(),
            sh,
            home,
            ro_binds,
            // Dropped on purpose (`qa_mounts` point 2): no operator creds overlay.
            config_overlays: Vec::new(),
            forwarded_config_dir: None,
        })
    }

    /// Resolve the fields shared by [`resolve`](SandboxHost::resolve) and
    /// [`resolve_for_qa`](SandboxHost::resolve_for_qa): the host `$HOME` (failing
    /// closed if unset — the sandbox cannot be assembled without a home to
    /// shadow), the `/bin/sh` backing shell, and the existing RO config binds.
    fn resolve_home_sh_ro(path_env: &str) -> Result<(PathBuf, PathBuf, Vec<PathBuf>), SpawnError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| !h.as_os_str().is_empty())
            .ok_or_else(|| SpawnError::BwrapMissing {
                searched: "HOME".to_owned(),
            })?;

        // `/bin/sh` backing shell: prefer the profile's bash, else any bash on
        // PATH, else fall back to the literal name (bwrap will error clearly if
        // it truly cannot be resolved).
        let sh = home
            .join(".nix-profile/bin/bash")
            .canonicalize()
            .ok()
            .or_else(|| resolve_on_path("bash", path_env))
            .unwrap_or_else(|| PathBuf::from("bash"));

        let ro_candidates = [
            home.join(".nix-profile"),
            home.join(".local/state/nix"),
            home.join(".config/git"),
            home.join(".config/jj"),
        ];
        let ro_binds = ro_candidates.into_iter().filter(|p| p.exists()).collect();

        Ok((home, sh, ro_binds))
    }

    /// The base bwrap mount policy — the essential subset of `claude-sandbox`'s
    /// bwrap args needed to run `claude` inside `nix-shell`, rendered as argv
    /// tokens (everything *before* the per-role matrix):
    ///
    /// - `--tmpfs <home>` — empty HOME (the worker never sees the operator's).
    /// - `--ro-bind /nix /nix` — the nix store (all binaries + the dev shell).
    /// - `--ro-bind /etc /etc` — DNS/`passwd`/`nix.conf`.
    /// - `--proc /proc`, `--dev /dev` — kernel filesystems.
    /// - `--tmpfs /run`, `--tmpfs /tmp` — private, empty scratch.
    /// - `--symlink <sh> /bin/sh` — programs that spawn `/bin/sh`.
    /// - `--ro-bind` of the existing RO config dirs (nix profile+state, git/jj
    ///   config).
    /// - `--overlay-src <dir> --tmp-overlay <dir>` of each existing claude
    ///   config dir — the worker reads the operator's credentials (RO lower
    ///   layer) but its writes land in an invisible tmpfs and are discarded, so
    ///   it cannot mutate the operator's config/credentials/hooks (finding #3).
    /// - `--setenv SHELL`, `--share-net`, `--unshare-pid`, `--chdir
    ///   <workspace>`.
    ///
    /// Deliberately omitted from `claude-sandbox`'s fuller policy (not needed to
    /// run a headless `claude`): the D-Bus/keyring socket, crossbridge socket
    /// (crossbridge is deferred), SSH agent/keys/known_hosts, zsh history,
    /// c8ctl, Maven, the podman service, and the non-NixOS `/usr`,`/lib*`,`/opt`
    /// compat binds (this host is NixOS-style, everything is under `/nix`).
    /// The workspace RW and `.jj/`/`.git/`/`.crosslink/` binds are **not** here —
    /// they are the per-role [`MountMatrix`], appended after this.
    ///
    /// **Commit-signing binds are intentionally omitted for the MVP (finding
    /// #5c).** The reference `claude-sandbox` also binds the SSH agent socket,
    /// `~/.ssh/*.pub`, `allowed_signers`, and the `gh` config so an agent can
    /// SSH-*sign* its commits. The real Implementer's *commit identity*
    /// (`user.name`/`user.email` for `jj describe` on the colocated backend)
    /// already works here via the `~/.config/jj` and `~/.config/git` RO binds
    /// above — signing is a separate, deployment-dependent concern. It is left
    /// out on purpose because (a) the live-`claude` Implementer path is not yet
    /// exercised (the MVP dogfoods the Direct path), and (b) enabling it is
    /// all-or-nothing: the SSH agent socket bind is useless without also adding
    /// `SSH_AUTH_SOCK` to the worker env allowlist (env hygiene scrubs it today),
    /// so binding half of it would be a false signal. TO RE-ENABLE when the live
    /// Implementer lands and the repo configures `signing.behavior`: add RO binds
    /// for `$SSH_AUTH_SOCK`, `~/.ssh/*.pub`, `~/.ssh/allowed_signers`, and the
    /// `gh` config, and add `SSH_AUTH_SOCK` to [`WORKER_ENV_ALLOWLIST`]. Until
    /// then, orchestrator workers should run with signing disabled
    /// (`signing.behavior = "drop"`), which needs none of these.
    pub fn base_mounts(&self, workspace: &Path) -> Vec<String> {
        let home = self.home.to_string_lossy().into_owned();
        let sh = self.sh.to_string_lossy().into_owned();
        let mut args = vec![
            "--tmpfs".to_owned(),
            home.clone(),
            "--ro-bind".to_owned(),
            "/nix".to_owned(),
            "/nix".to_owned(),
            "--ro-bind".to_owned(),
            "/etc".to_owned(),
            "/etc".to_owned(),
            "--proc".to_owned(),
            "/proc".to_owned(),
            "--dev".to_owned(),
            "/dev".to_owned(),
            "--tmpfs".to_owned(),
            "/run".to_owned(),
            "--tmpfs".to_owned(),
            "/tmp".to_owned(),
            "--symlink".to_owned(),
            sh.clone(),
            "/bin/sh".to_owned(),
        ];
        for ro in &self.ro_binds {
            Mount {
                source: ro.clone(),
                mode: MountMode::ReadOnly,
            }
            .render_into(&mut args);
        }
        // Claude config dirs: exposed write-discarding (host RO lower + tmpfs
        // upper) so the worker authenticates but cannot mutate the operator's
        // config (finding #3). `--overlay-src` sets the lower layer for the
        // `--tmp-overlay` that follows it.
        for cfg in &self.config_overlays {
            let dir = cfg.to_string_lossy().into_owned();
            args.push("--overlay-src".to_owned());
            args.push(dir.clone());
            args.push("--tmp-overlay".to_owned());
            args.push(dir);
        }
        args.extend([
            "--setenv".to_owned(),
            "SHELL".to_owned(),
            sh,
            "--share-net".to_owned(),
            "--unshare-pid".to_owned(),
            "--chdir".to_owned(),
            workspace.to_string_lossy().into_owned(),
        ]);
        args
    }

    /// The **hermetic** bwrap mount policy for the static QA gate (P0 threat-model
    /// fix, closes T1). Rendered as argv tokens, exactly like [`base_mounts`], but
    /// deliberately diverging on the three points that make QA a *grading* sandbox
    /// rather than a live-`claude` sandbox:
    ///
    /// 1. **Network denied — `--unshare-net`, never `--share-net`.** bwrap shares
    ///    the host network namespace unless it is explicitly unshared; the worker
    ///    path never unshares net (a live `claude` needs the Anthropic API), so QA
    ///    must *actively* add `--unshare-net`. The QA script is `cargo test
    ///    --locked --offline` — already hermetic — so denying egress removes the
    ///    exfiltration channel worker-authored `build.rs`/test code would
    ///    otherwise have.
    /// 2. **No Claude-creds overlay.** [`base_mounts`] exposes the operator's
    ///    `claude` config dirs write-discarding so a live worker can authenticate;
    ///    QA never runs `claude`, so exposing operator credentials to the
    ///    worker-authored code *under test* is exactly the leak this gate closes.
    ///    The `config_overlays` are omitted here.
    /// 3. **Workspace bound RW here.** The worker path appends the workspace via
    ///    the per-role [`MountMatrix`]; QA does not use the matrix (it needs no
    ///    repository `.jj/`/`.git/`/`.crosslink/`), so it binds *only* the
    ///    workspace RW — `cargo` must write `target/` — and nothing else of the
    ///    repository.
    ///
    /// Everything else matches [`base_mounts`] and shares the same constants: the
    /// tmpfs HOME, `/nix` RO, `/etc` RO, `/proc`, `/dev`, `/run`+`/tmp` tmpfs, the
    /// `/bin/sh` symlink, the RO config binds ([`ro_binds`] — kept: the nix-profile
    /// bind is load-bearing so `PATH` resolves `bash`/`cargo` inside the namespace,
    /// and the git/jj config binds are harmless RO), `--setenv SHELL`,
    /// `--unshare-pid`, and `--chdir <workspace>`.
    ///
    /// [`base_mounts`]: SandboxHost::base_mounts
    /// [`ro_binds`]: SandboxHost#structfield.ro_binds
    pub fn qa_mounts(&self, workspace: &Path) -> Vec<String> {
        let home = self.home.to_string_lossy().into_owned();
        let sh = self.sh.to_string_lossy().into_owned();
        let mut args = vec![
            "--tmpfs".to_owned(),
            home,
            "--ro-bind".to_owned(),
            "/nix".to_owned(),
            "/nix".to_owned(),
            "--ro-bind".to_owned(),
            "/etc".to_owned(),
            "/etc".to_owned(),
            "--proc".to_owned(),
            "/proc".to_owned(),
            "--dev".to_owned(),
            "/dev".to_owned(),
            "--tmpfs".to_owned(),
            "/run".to_owned(),
            "--tmpfs".to_owned(),
            "/tmp".to_owned(),
            "--symlink".to_owned(),
            sh.clone(),
            "/bin/sh".to_owned(),
        ];
        for ro in &self.ro_binds {
            Mount {
                source: ro.clone(),
                mode: MountMode::ReadOnly,
            }
            .render_into(&mut args);
        }
        // NO `config_overlays` here (point 2): QA must not expose operator Claude
        // credentials to the worker-authored code it grades.
        //
        // The workspace, bound RW so `cargo` can write `target/` (point 3). This
        // is the ONLY repository path QA sees — no `<root>/.jj`, `.git`, or
        // `.crosslink` (QA needs none of them).
        Mount {
            source: workspace.to_path_buf(),
            mode: MountMode::ReadWrite,
        }
        .render_into(&mut args);
        args.extend([
            "--setenv".to_owned(),
            "SHELL".to_owned(),
            sh,
            // Hermetic: deny host network entirely (point 1). The fixture QA is
            // `--offline`, so this severs egress without breaking the check.
            "--unshare-net".to_owned(),
            "--unshare-pid".to_owned(),
            // Reap the whole sandbox if the orchestrator dies without running the
            // explicit kill path: bwrap sends SIGKILL to the sandbox (and its
            // pid-ns, tearing down `cargo`/`rustc`) when its parent exits. This
            // COMPLEMENTS — does not replace — the timeout-kill in `QaGate::run`,
            // which is still what reaps a *running* gate on a hang; this only
            // covers the orchestrator-crashed-mid-run case that the kill path
            // never reaches.
            "--die-with-parent".to_owned(),
            "--chdir".to_owned(),
            workspace.to_string_lossy().into_owned(),
        ]);
        args
    }
}

// ============================================================================
// Store-path pin guard (REQ-4a / AC-19)
// ============================================================================

/// The `bwrap` **store-path** pin the orchestrator was configured with
/// (REQ-4a). `bwrap` is the isolation boundary the per-role mount matrix is
/// enforced through, so *it* is what must be pinned. The dev shell captures the
/// resolved nix store path — e.g.
/// `/nix/store/<hash>-bubblewrap-0.11.2/bin/bwrap` — into [`BWRAP_PIN_ENV`] at
/// shell entry. Because a nix store path is content-addressed, that path *is*
/// the exact pinned build: two different bubblewrap versions live at two
/// different store paths. So verification is **path identity**, not a version
/// string.
///
/// [`verify`](Self::verify) resolves `bwrap` on `PATH`, canonicalizes it to its
/// real target, and requires it to **equal** the pinned path exactly. This
/// fails closed:
///
/// - An empty/unset pin ⇒ error (no accept-all fallback).
/// - `bwrap` not resolvable on `PATH` ⇒ error.
/// - A shim at a *different* path (e.g. a PATH-injected fake) ⇒ mismatch error,
///   even if it names itself `bwrap`.
///
/// A newtype over the pinned path so a real spawn can only be guarded, never
/// compared against a bare `&str` a caller might forget to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPin {
    expected: String,
}

impl SandboxPin {
    /// The pin the orchestrator was configured with (the resolved
    /// [`BWRAP_PIN_ENV`] store path).
    pub fn new(expected: impl Into<String>) -> Self {
        SandboxPin {
            expected: expected.into(),
        }
    }

    /// Read the pin from [`BWRAP_PIN_ENV`]. Returns [`SpawnError::BwrapMissing`]
    /// if the variable is unset or empty — a real spawn cannot proceed without a
    /// pin (REQ-4a, fail-closed).
    pub fn from_env() -> Result<Self, SpawnError> {
        match std::env::var(BWRAP_PIN_ENV) {
            Ok(v) if !v.is_empty() => Ok(SandboxPin::new(v)),
            _ => Err(SpawnError::BwrapMissing {
                searched: BWRAP_PIN_ENV.to_owned(),
            }),
        }
    }

    /// The expected pinned store path.
    pub fn expected(&self) -> &str {
        &self.expected
    }

    /// Resolve `bwrap` on `PATH` and confirm it is the exact pinned store path
    /// (REQ-4a / AC-19).
    ///
    /// - Empty pin ⇒ [`SpawnError::BwrapMissing`] (fail-closed; there is no
    ///   accept-all).
    /// - `bwrap` not found on `PATH`, or unreadable ⇒
    ///   [`SpawnError::BwrapMissing`].
    /// - Resolved real path ≠ pinned path ⇒ [`SpawnError::BwrapPinMismatch`]
    ///   (the AC-19 refusal).
    ///
    /// The comparison canonicalizes both sides with [`std::fs::canonicalize`]
    /// (resolving symlinks such as the `~/.nix-profile/bin/bwrap` profile link
    /// down to the underlying `/nix/store/…` file) so identity is judged on the
    /// real store path, not on which symlink `PATH` happened to hit.
    pub fn verify(&self) -> Result<(), SpawnError> {
        if self.expected.is_empty() {
            // Fail closed: an unconfigured pin must never accept whatever
            // `bwrap` happens to be first on PATH.
            return Err(SpawnError::BwrapMissing {
                searched: BWRAP_PIN_ENV.to_owned(),
            });
        }

        let path_env = std::env::var("PATH").unwrap_or_default();
        let resolved =
            resolve_on_path(BWRAP_BIN, &path_env).ok_or_else(|| SpawnError::BwrapMissing {
                searched: path_env.clone(),
            })?;

        // Canonicalize both sides so we compare real store paths, not the
        // profile symlink vs. its target.
        let resolved_real =
            std::fs::canonicalize(&resolved).map_err(|_| SpawnError::BwrapMissing {
                searched: path_env.clone(),
            })?;
        // The pin may itself be a symlink-free store path; canonicalize best
        // effort, falling back to the raw pin if it can't be resolved (e.g. a
        // test pin that doesn't exist on disk — that simply won't match a real
        // resolved path, which is the correct fail-closed outcome).
        let expected_real =
            std::fs::canonicalize(&self.expected).unwrap_or_else(|_| PathBuf::from(&self.expected));

        if resolved_real == expected_real {
            Ok(())
        } else {
            Err(SpawnError::BwrapPinMismatch {
                expected: self.expected.clone(),
                found: resolved_real.to_string_lossy().into_owned(),
            })
        }
    }
}

/// Resolve `program` against a `PATH` string, returning the first existing
/// entry. Mirrors the shell's PATH lookup without shelling out (AC-24): an
/// absolute/relative `program` is returned as-is if it exists; otherwise each
/// `PATH` component is tried in order.
fn resolve_on_path(program: &str, path_env: &str) -> Option<PathBuf> {
    let candidate = Path::new(program);
    if candidate.is_absolute() || program.contains('/') {
        return candidate.exists().then(|| candidate.to_path_buf());
    }
    std::env::split_paths(path_env)
        .map(|dir| dir.join(program))
        .find(|p| p.exists())
}

// ============================================================================
// Spawner + SpawnOutcome
// ============================================================================

/// The typed result of hosting a worker: a live [`PaneHandle`] plus the
/// workspace it runs in. The caller waits on it via [`WorkerHandle::wait`] and,
/// once the worker exits, checks the DONE sentinel with S3's
/// [`crate::artifacts::DoneSentinel`] — spawn does not parse artifacts.
#[derive(Debug, Clone)]
pub struct WorkerHandle {
    /// The zellij pane hosting the worker.
    pub pane: PaneHandle,
    /// The workspace directory the worker runs in.
    pub workspace: PathBuf,
}

/// The outcome of waiting on a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnOutcome {
    /// The worker's command exited (the pane closed). The orchestrator now
    /// checks the DONE sentinel to decide success vs. crash (REQ-3b).
    Exited,
    /// The wait timed out with the worker still running — the caller decides
    /// whether to keep waiting or treat it as a stall (REQ-11 watchdog owns the
    /// staleness policy; this just reports liveness).
    StillRunning,
}

impl WorkerHandle {
    /// Poll the pane until the worker exits or `timeout` elapses, sleeping
    /// `poll_interval` between checks. Returns [`SpawnOutcome::Exited`] once the
    /// pane closes (workers use `--close-on-exit`), or
    /// [`SpawnOutcome::StillRunning`] if the deadline passes first.
    ///
    /// A *transient* liveness-query failure is not fatal: zellij's
    /// `list-panes --json` can momentarily return unparseable/empty output while
    /// its shared server is busy, and one such hiccup must not abort a worker
    /// wait. Such errors are retried until the deadline; only if the deadline
    /// passes without any clean read is the last error surfaced (wrapped as
    /// [`SpawnError::ZellijPaneCreateFailed`], the pane-scoped zellij variant).
    pub fn wait(
        &self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<SpawnOutcome, SpawnError> {
        let deadline = Instant::now() + timeout;
        loop {
            match pane_alive(&self.pane) {
                Ok(false) => return Ok(SpawnOutcome::Exited),
                Ok(true) => {
                    if Instant::now() >= deadline {
                        return Ok(SpawnOutcome::StillRunning);
                    }
                }
                // Transient (e.g. an empty `list-panes` while the shared zellij
                // server is busy): keep polling until the deadline in case the
                // next read succeeds; surface it only if the deadline passes.
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(SpawnError::ZellijPaneCreateFailed {
                            pane_name: self.pane.name.clone(),
                            source: Box::new(e),
                        });
                    }
                }
            }
            std::thread::sleep(poll_interval);
        }
    }

    /// Best-effort close of the pane. A pane that already closed itself is not
    /// an error here — closing an exited pane is idempotent from the caller's
    /// view.
    pub fn close(&self) {
        let _ = pane_close(&self.pane);
    }

    /// Close the pane **and verify the hosted command is actually gone** before
    /// returning — the workspace-cleanup safety step (#3).
    ///
    /// A failure/timeout path in the pump follows this with `jj workspace
    /// forget` + `rm -rf`. Doing that while a surviving worker still writes into
    /// the workspace races the removal (partial trees, resurrected files) and
    /// leaks the process. So on any such path the pump calls this first: it
    /// closes the pane (which terminates the pane's foreground command via
    /// zellij's `close-pane`) and then polls [`pane_alive`] until the pane is
    /// reported dead or `deadline` elapses. Returns `true` if the pane was
    /// confirmed gone, `false` if the deadline passed with the pane still (or
    /// still-appearing-to-be) alive — the caller logs the residual risk but
    /// proceeds, since leaving the workspace forever is worse.
    ///
    /// RESIDUAL LIMITATION (documented follow-up, mirrors the QA-grandchild
    /// note): workers are hosted through the `zellij` CLI, so the orchestrator
    /// never learns the worker's OS pid (there is no per-pane pid in zellij's
    /// IPC surface — see REQ-1d). `close-pane` terminates the pane's foreground
    /// command, but a *grandchild* the worker spawned into its own process group
    /// (e.g. a detached background job) can outlive the pane. A full
    /// process-group kill needs a signal crate / `unsafe`, which this crate's
    /// `#![forbid(unsafe_code)]` disallows; portably we do pane-close + verified
    /// death of the pane. Persisting a real pid and group-killing it is tracked
    /// as follow-up (#16 P2 crash-recovery).
    pub fn close_and_wait(&self, deadline: Duration, poll_interval: Duration) -> bool {
        self.close();
        let stop = Instant::now() + deadline;
        loop {
            match pane_alive(&self.pane) {
                // Confirmed gone: the pane closed on command exit / close-pane.
                Ok(false) => return true,
                Ok(true) => {
                    if Instant::now() >= stop {
                        return false;
                    }
                }
                // A transient liveness-query hiccup: keep polling until the
                // deadline. If it never clears, report unconfirmed.
                Err(_) => {
                    if Instant::now() >= stop {
                        return false;
                    }
                }
            }
            std::thread::sleep(poll_interval);
        }
    }
}

/// Hosts workers in panes of a headless zellij session (REQ-1d).
///
/// Holds the [`SessionHandle`] (created by
/// [`vetinari_zellij_host::session_ensure`]), the repository `root`, and the
/// [`SandboxPin`] the store-path pin guard checks. A single [`Spawner`] serves
/// every spawn, so the pin is checked from one place and cannot be bypassed.
pub struct Spawner {
    session: SessionHandle,
    root: PathBuf,
    pin: SandboxPin,
}

impl Spawner {
    /// Build a spawner hosting workers in `session`, rooted at `root`, guarding
    /// real spawns against `pin`.
    pub fn new(session: SessionHandle, root: impl Into<PathBuf>, pin: SandboxPin) -> Self {
        Spawner {
            session,
            root: root.into(),
            pin,
        }
    }

    /// Build a spawner whose pin is loaded from the environment
    /// ([`SandboxPin::from_env`] / [`BWRAP_PIN_ENV`]) — the production
    /// constructor. Fails closed with [`SpawnError::BwrapMissing`] if the pin is
    /// unset, so an orchestrator cannot start real `claude` spawns without a
    /// configured pin (REQ-4a). Tests that don't exercise the real path use
    /// [`Spawner::new`] with an explicit pin instead.
    pub fn from_env(session: SessionHandle, root: impl Into<PathBuf>) -> Result<Self, SpawnError> {
        Ok(Spawner::new(session, root, SandboxPin::from_env()?))
    }

    /// The repository root this spawner hosts workers under.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The configured version pin.
    pub fn pin(&self) -> &SandboxPin {
        &self.pin
    }

    /// Spawn `command` into `workspace`'s directory, hosting it in a pane named
    /// `<role>-<issue>-r<round>` in this spawner's session (REQ-1d).
    ///
    /// For [`WorkerCommand::Claude`] the store-path pin guard (REQ-4a / AC-19)
    /// runs **first**: if the `bwrap` resolved on PATH is not the exact pinned
    /// nix store path, [`SpawnError::BwrapPinMismatch`] is returned and *no*
    /// pane is created. For [`WorkerCommand::Direct`] the guard is skipped (the
    /// dogfood path).
    ///
    /// Returns a [`WorkerHandle`] the caller waits on; spawn itself does not
    /// parse artifacts (the orchestrator checks the DONE sentinel afterward).
    pub fn spawn(
        &self,
        role: WorkerRole,
        issue_id: &str,
        round: u32,
        workspace: &PreparedWorkspace,
        command: &WorkerCommand,
    ) -> Result<WorkerHandle, SpawnError> {
        let pane_name = PaneName::new(role, issue_id, round);

        // Assemble the worker's own argv + any explicit extra env from the
        // command kind. For the real path this also runs the pin guard — a
        // caller cannot reach pane creation without it having passed.
        let (worker_argv, extra_env): (Vec<String>, Vec<(String, String)>) = match command {
            WorkerCommand::Direct { argv, env } => {
                if argv.is_empty() {
                    return Err(SpawnError::WorkspacePathConflict {
                        path: workspace.path().to_path_buf(),
                    });
                }
                (argv.clone(), env.clone())
            }
            WorkerCommand::Claude(spawn) => {
                // REQ-4a / AC-19: refuse to spawn unless the `bwrap` on PATH is
                // the exact pinned store path, BEFORE the pane exists.
                self.pin.verify()?;
                // Resolve the host binaries + base binds now (the pin is the
                // verified bwrap path).
                let host = SandboxHost::resolve(&self.pin)?;
                // The real path enters `<workspace>/shell.nix`; a workspace
                // without it would fail deep inside bwrap with an opaque
                // nix-shell error. Fail early with a typed, actionable error
                // (finding #5). (The `hello` dogfood fixture has no shell.nix
                // and so uses the Direct path, which never reaches here.)
                let shell_nix = workspace.path().join(SHELL_NIX_FILE);
                if !shell_nix.exists() {
                    return Err(SpawnError::ShellNixMissing { path: shell_nix });
                }
                // Deliver the round's task as a file the worker reads (REQ-8),
                // before the pane exists so it is present when claude starts.
                write_task_file(workspace.path(), &spawn.task)?;
                // Scope the CLAUDE_CONFIG_DIR passthrough to the live `claude`
                // worker (findings #2 + creds-scope): forward the *resolved*
                // config dir (guaranteed exposed into the sandbox), never the
                // ambient value, and never to a Direct worker. `None` ⇒ forward
                // nothing and let claude use its default resolution.
                let env = match host.forwarded_config_dir() {
                    Some(dir) => vec![(
                        CLAUDE_CONFIG_DIR_ENV.to_owned(),
                        dir.to_string_lossy().into_owned(),
                    )],
                    None => Vec::new(),
                };
                (spawn.to_argv(workspace.path(), &host), env)
            }
        };

        // Env hygiene: prepend `env -i <allowlist> <extra>` so the worker starts
        // from a cleared environment (no orchestrator API keys, tokens, or the
        // pin) plus only the minimal allowlist and any caller-supplied env. The
        // extra env is folded into the prefix rather than passed through
        // zellij's own `env` mechanism, so `env -i` clears first and these are
        // the *only* variables the worker sees.
        let mut argv = scrub_env_prefix(&extra_env);
        argv.extend(worker_argv);

        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();

        let pane = vetinari_zellij_host::pane_create(
            &self.session,
            &pane_name.as_str(),
            &argv_refs,
            &[],
            workspace.path(),
        )
        .map_err(|e| SpawnError::ZellijPaneCreateFailed {
            pane_name: pane_name.as_str(),
            source: Box::new(e),
        })?;

        Ok(WorkerHandle {
            pane,
            workspace: workspace.path().to_path_buf(),
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from("/repo")
    }

    fn ws() -> PathBuf {
        PathBuf::from("/repo/.workspace/implementing-42-r0-a1b2c3d4")
    }

    // --- PaneName -----------------------------------------------------------

    #[test]
    fn pane_name_renders_role_issue_round() {
        let name = PaneName::new(WorkerRole::Implementer, "42", 0);
        assert_eq!(name.as_str(), "implementer-42-r0");
        let name = PaneName::new(WorkerRole::Adversary, "#7", 3);
        assert_eq!(name.as_str(), "adversary-7-r3");
        let name = PaneName::new(WorkerRole::Merger, "L3", 12);
        assert_eq!(name.as_str(), "merger-l3-r12");
    }

    #[test]
    fn pane_name_folds_empty_issue() {
        // An all-punctuation issue must not render `<role>--r<round>`.
        let name = PaneName::new(WorkerRole::Implementer, "###", 0);
        assert_eq!(name.as_str(), "implementer-issue-r0");
        assert!(!name.as_str().contains("--"));
    }

    // --- MountMatrix: per-role bind surface ---------------------------------

    fn sources(m: &MountMatrix) -> Vec<PathBuf> {
        m.mounts()
            .iter()
            .map(|mount| mount.source.clone())
            .collect()
    }

    fn mode_of(m: &MountMatrix, leaf: &str) -> Option<MountMode> {
        m.mounts()
            .iter()
            .find(|mount| mount.source.file_name().is_some_and(|n| n == leaf))
            .map(|mount| mount.mode)
    }

    #[test]
    fn implementer_mount_matrix() {
        let m = MountMatrix::for_role(WorkerRole::Implementer, &root(), &ws());
        // Workspace RW + .jj/ RW + .git/ RW + .crosslink/ RO.
        assert!(m.has_jj(), "Implementer must see .jj/");
        assert_eq!(mode_of(&m, ".jj"), Some(MountMode::ReadWrite));
        assert_eq!(mode_of(&m, ".crosslink"), Some(MountMode::ReadOnly));
        // The colocated .git/ backend travels with .jj/, bound RW (finding #1).
        assert!(m.has_git(), "Implementer must see the colocated .git/");
        assert_eq!(mode_of(&m, ".git"), Some(MountMode::ReadWrite));
        // The workspace dir is bound RW.
        assert_eq!(
            m.mounts()[0],
            Mount {
                source: ws(),
                mode: MountMode::ReadWrite
            }
        );
        // Never .orchestrator/ (REQ-6).
        let srcs = sources(&m);
        assert!(
            !srcs.iter().any(|s| s.ends_with(".orchestrator")),
            "no .orchestrator/ mount"
        );
    }

    #[test]
    fn adversary_never_gets_jj_or_git() {
        let m = MountMatrix::for_role(WorkerRole::Adversary, &root(), &ws());
        assert!(!m.has_jj(), "Adversary must NEVER see .jj/ (REQ-5, REQ-5a)");
        // Without .jj/ the colocated .git/ is withheld too (finding #1).
        assert!(!m.has_git(), "Adversary must NEVER see the repo .git/");
        // Still has workspace RW + .crosslink/ RO.
        assert_eq!(mode_of(&m, ".crosslink"), Some(MountMode::ReadOnly));
        assert_eq!(m.mounts()[0].mode, MountMode::ReadWrite);
        let srcs = sources(&m);
        assert!(!srcs.iter().any(|s| s.ends_with(".orchestrator")));
    }

    #[test]
    fn merger_matrix_matches_implementer_binds() {
        let imp = MountMatrix::for_role(WorkerRole::Implementer, &root(), &ws());
        let mrg = MountMatrix::for_role(WorkerRole::Merger, &root(), &ws());
        // Merger sees the same bind surface as the Implementer (.jj/ + .git/ RW).
        assert!(mrg.has_jj());
        assert!(mrg.has_git());
        assert_eq!(imp.mounts(), mrg.mounts());
    }

    #[test]
    fn git_travels_with_jj_and_orchestrator_is_never_mounted() {
        for role in [
            WorkerRole::Implementer,
            WorkerRole::Adversary,
            WorkerRole::Merger,
            WorkerRole::Judge,
        ] {
            let m = MountMatrix::for_role(role, &root(), &ws());
            // The colocated .git/ is bound iff .jj/ is (finding #1): they are one
            // repository, granted together to the committing roles only.
            assert_eq!(
                m.has_git(),
                m.has_jj(),
                "{role:?}: .git/ must be present exactly when .jj/ is"
            );
            // `.orchestrator/` is never mounted for any role (REQ-6).
            for mount in m.mounts() {
                assert!(
                    !mount.source.ends_with(".orchestrator"),
                    "{role:?} must never mount .orchestrator/"
                );
            }
        }
    }

    // --- ClaudeSpawn argv assembly (pure; REQ-4, REQ-5/6/7, REQ-13) ---------

    fn spawn_for(
        role: WorkerRole,
        allowlist: &str,
        denylist: &str,
        prompt: &str,
        max_turns: u32,
    ) -> ClaudeSpawn {
        match WorkerCommand::claude(
            role,
            &root(),
            &ws(),
            "do the thing",
            allowlist,
            denylist,
            prompt,
            max_turns,
        ) {
            WorkerCommand::Claude(s) => s,
            _ => unreachable!(),
        }
    }

    fn implementer_spawn() -> ClaudeSpawn {
        spawn_for(
            WorkerRole::Implementer,
            "Bash(jj describe),Read,Edit,Write",
            "Bash(git:*),Bash(jj abandon:*)",
            "You are the Implementer.",
            80,
        )
    }

    /// A deterministic, filesystem-independent host so `to_argv` is exercised as
    /// a pure function (no env/FS probing).
    fn test_host() -> SandboxHost {
        SandboxHost::new(
            "/nix/store/hash-bubblewrap/bin/bwrap",
            "/nix/store/hash-nix/bin/nix-shell",
            "/nix/store/hash-bash/bin/bash",
            "/home/op",
            vec![PathBuf::from("/home/op/.nix-profile")],
            vec![PathBuf::from("/home/op/.config/claude")],
            Some(PathBuf::from("/home/op/.config/claude")),
        )
    }

    #[test]
    fn claude_argv_has_required_flags_and_no_dangerous_skip() {
        // The inner `claude` command is the REQ-4/REQ-13 flag contract.
        let cargv = implementer_spawn().claude_argv();
        assert_eq!(cargv[0], CLAUDE_BIN);
        // Headless start: `-p` with the bootstrap prompt, or the worker never
        // begins (a pane has no stdin for an interactive REPL). The bootstrap
        // points at the task file.
        assert!(
            cargv.windows(2).any(|w| w[0] == "-p" && w[1] == HEADLESS_BOOTSTRAP),
            "REQ-8/finding #4: headless `-p <bootstrap>` must be present so the worker starts: {cargv:?}"
        );
        assert!(
            HEADLESS_BOOTSTRAP.contains("_orchestrator/task.md"),
            "the bootstrap must point the worker at its task file"
        );
        assert!(cargv
            .windows(2)
            .any(|w| w == ["--permission-mode", "default"]));
        // The belt-and-suspenders deny list rides through for known-dangerous
        // VCS verbs (clean refusal, no headless-hanging prompt).
        assert!(
            cargv
                .windows(2)
                .any(|w| w[0] == "--disallowed-tools" && w[1] == "Bash(git:*),Bash(jj abandon:*)"),
            "the configured deny list must be emitted as --disallowed-tools: {cargv:?}"
        );
        assert!(cargv
            .windows(2)
            .any(|w| w[0] == "--allowed-tools" && w[1] == "Bash(jj describe),Read,Edit,Write"));
        // The appended system prompt carries the caller's role prompt AND the
        // fixed instruction to read the task file (REQ-8, finding #2).
        let prompt = cargv
            .windows(2)
            .find(|w| w[0] == "--append-system-prompt")
            .map(|w| w[1].clone())
            .expect("--append-system-prompt present");
        assert!(
            prompt.contains("You are the Implementer."),
            "role prompt must be preserved: {prompt}"
        );
        assert!(
            prompt.contains("_orchestrator/task.md"),
            "system prompt must instruct the worker to read its task file: {prompt}"
        );
        assert!(cargv
            .windows(2)
            .any(|w| w[0] == "--max-turns" && w[1] == "80"));
        // REQ-4: NEVER --dangerously-skip-permissions.
        assert!(
            !cargv.iter().any(|a| a == "--dangerously-skip-permissions"),
            "REQ-4: must never pass --dangerously-skip-permissions"
        );
        // The task itself is delivered as a file, never on argv/stdin.
        assert!(!cargv.iter().any(|a| a == "do the thing"));
    }

    #[test]
    fn to_argv_is_a_direct_bwrap_invocation() {
        let host = test_host();
        let argv = implementer_spawn().to_argv(&ws(), &host);

        // Leads with the pinned bwrap store path, never claude-sandbox.
        assert_eq!(argv[0], "/nix/store/hash-bubblewrap/bin/bwrap");
        assert!(!argv.iter().any(|a| a == "claude-sandbox"));

        // Essential base mounts are present.
        assert!(argv.windows(2).any(|w| w == ["--tmpfs", "/home/op"]));
        assert!(argv.windows(3).any(|w| w == ["--ro-bind", "/nix", "/nix"]));
        assert!(argv.windows(3).any(|w| w == ["--ro-bind", "/etc", "/etc"]));
        assert!(argv
            .windows(2)
            .any(|w| w == ["--chdir", &ws().to_string_lossy()]));

        // After the `--`, nix-shell enters <ws>/shell.nix and --runs claude.
        let sep = argv.iter().position(|a| a == "--").expect("separator");
        assert_eq!(argv[sep + 1], "/nix/store/hash-nix/bin/nix-shell");
        assert_eq!(argv[sep + 2], ws().join(SHELL_NIX_FILE).to_string_lossy());
        assert_eq!(argv[sep + 3], "--run");
        let run = &argv[sep + 4];
        assert!(run.starts_with("claude "), "run string: {run}");
        assert!(run.contains("--permission-mode default"));
        assert!(run.contains("--max-turns 80"));
        assert!(!run.contains("--dangerously-skip-permissions"));
        // The allowlist (which contains a space) is shell-quoted in the string.
        assert!(run.contains("'Bash(jj describe),Read,Edit,Write'"));
    }

    /// The Implementer's argv binds `.jj/` RW, the colocated `.git/` RW, and
    /// `.crosslink/` RO; never `.orchestrator/`; the workspace is bound RW
    /// (REQ-5/6/7 with the finding-#1 amendment — ENFORCED).
    #[test]
    fn implementer_argv_renders_the_enforced_mount_matrix() {
        let argv = implementer_spawn().to_argv(&ws(), &test_host());
        let mounts = &argv[..argv.iter().position(|a| a == "--").unwrap()];

        // `.jj/` bound read-write.
        let jj = root().join(".jj");
        assert!(bound(mounts, "--bind", &jj), "Implementer must --bind .jj/");
        // The colocated `.git/` bound read-write (finding #1).
        let git = root().join(".git");
        assert!(
            bound(mounts, "--bind", &git),
            "Implementer must --bind the colocated .git/"
        );
        // `.crosslink/` bound read-only.
        let cross = root().join(".crosslink");
        assert!(
            bound(mounts, "--ro-bind", &cross),
            "must --ro-bind .crosslink/"
        );
        // workspace bound read-write.
        assert!(
            bound(mounts, "--bind", &ws()),
            "workspace must be --bind RW"
        );
        // Never `.orchestrator/`, at any mode.
        assert!(
            !any_bind_ends_with(mounts, ".orchestrator"),
            "no .orchestrator/ bind"
        );
    }

    /// The Adversary's argv NEVER binds `.jj/` (REQ-5, REQ-5a) — this is the
    /// whole point of the enforcement — while still binding workspace + crosslink.
    #[test]
    fn adversary_argv_carries_no_jj_bind() {
        let spawn = spawn_for(
            WorkerRole::Adversary,
            "Read",
            "",
            "You are the Adversary.",
            40,
        );
        let argv = spawn.to_argv(&ws(), &test_host());
        let mounts = &argv[..argv.iter().position(|a| a == "--").unwrap()];

        // No `.jj` path is bound anywhere (base mounts don't bind it either).
        assert!(
            !any_bind_ends_with(mounts, ".jj"),
            "Adversary argv must not bind .jj/"
        );
        // But it DOES see the workspace (RW) and .crosslink/ (RO).
        assert!(bound(mounts, "--bind", &ws()));
        assert!(bound(mounts, "--ro-bind", &root().join(".crosslink")));
        assert!(!any_bind_ends_with(mounts, ".git"));
        assert!(!any_bind_ends_with(mounts, ".orchestrator"));
        // And its turn cap still rides through to the run string.
        let run = argv.last().unwrap();
        assert!(run.contains("--max-turns 40"));
    }

    /// True if `mounts` contains the token triple `[flag, path, path]`.
    fn bound(mounts: &[String], flag: &str, path: &Path) -> bool {
        let p = path.to_string_lossy();
        mounts
            .windows(3)
            .any(|w| w[0] == flag && w[1] == p && w[2] == p)
    }

    /// True if any `--bind`/`--ro-bind` source in `mounts` ends with `leaf`.
    fn any_bind_ends_with(mounts: &[String], leaf: &str) -> bool {
        mounts
            .windows(2)
            .any(|w| (w[0] == "--bind" || w[0] == "--ro-bind") && Path::new(&w[1]).ends_with(leaf))
    }

    #[test]
    fn shell_quote_escapes_correctly() {
        assert_eq!(shell_quote("Read"), "Read");
        assert_eq!(shell_quote("Bash(jj describe)"), "'Bash(jj describe)'");
        // Embedded single quote is escaped as '\''.
        assert_eq!(shell_quote("a'b"), r#"'a'\''b'"#);
        assert_eq!(shell_quote(""), "''");
    }

    // --- SandboxPin: store-path identity (fail-closed) ----------------------

    #[test]
    fn empty_pin_fails_closed() {
        // An unset/empty pin must NEVER accept-all — it errors before even
        // resolving anything on PATH.
        let err = SandboxPin::new("").verify().unwrap_err();
        assert!(
            matches!(err, SpawnError::BwrapMissing { .. }),
            "empty pin must fail closed, got {err:?}"
        );
    }

    #[test]
    fn resolve_on_path_finds_first_hit() {
        let dir = tempfile::tempdir().expect("tmp");
        let bin = dir.path().join("bwrap");
        std::fs::write(&bin, "").expect("write");
        let path_env = dir.path().to_string_lossy().into_owned();
        assert_eq!(
            resolve_on_path("bwrap", &path_env).as_deref(),
            Some(bin.as_path())
        );
        // A name not on PATH resolves to nothing.
        assert!(resolve_on_path("definitely-not-here-xyz", &path_env).is_none());
    }

    // Store-path pass/fail through the live `verify()` (which mutates the
    // process-global PATH) is exercised in `tests/spawn_dispatch.rs`, where the
    // integration crate can use the `unsafe` PATH-swap helper; this crate
    // `#![forbid(unsafe_code)]`, so the pure pieces are tested here instead.

    // --- env scrub prefix ----------------------------------------------------

    #[test]
    fn scrub_prefix_clears_and_allowlists() {
        let prefix = scrub_env_prefix(&[("EXTRA".to_owned(), "1".to_owned())]);
        // Always leads with `env -i` (clear the inherited environment).
        assert_eq!(&prefix[..2], &["env", "-i"]);
        // The caller-supplied extra is forwarded.
        assert!(prefix.iter().any(|a| a == "EXTRA=1"));
        // Only allowlisted names (plus extras) ever appear — never a bare
        // secret name. Every assignment's key must be allowlisted or `EXTRA`.
        for entry in &prefix[2..] {
            let key = entry.split('=').next().unwrap_or("");
            assert!(
                WORKER_ENV_ALLOWLIST.contains(&key) || key == "EXTRA",
                "unexpected env key leaked into worker: {entry}"
            );
        }
    }

    #[test]
    fn direct_worker_command_builder() {
        let cmd = WorkerCommand::direct(["bash", "fake.sh"], [("K", "V")]);
        match cmd {
            WorkerCommand::Direct { argv, env } => {
                assert_eq!(argv, vec!["bash".to_owned(), "fake.sh".to_owned()]);
                assert_eq!(env, vec![("K".to_owned(), "V".to_owned())]);
            }
            _ => panic!("expected Direct"),
        }
    }

    // --- task delivery (REQ-8, finding #2) ----------------------------------

    #[test]
    fn write_task_file_creates_orchestrator_task_md() {
        // The task is delivered as `_orchestrator/task.md` (not stdin): the
        // helper creates the parent and writes the exact content.
        let dir = tempfile::tempdir().expect("tmp workspace");
        let task = "Implement REQ-42.\n\nPrior findings: none.";
        write_task_file(dir.path(), task).expect("write task file");

        let written = dir.path().join(TASK_FILE);
        assert!(
            written.ends_with("_orchestrator/task.md"),
            "correct rel path"
        );
        assert_eq!(
            std::fs::read_to_string(&written).expect("read back task"),
            task,
            "task.md must carry the exact task content"
        );
    }

    #[test]
    fn write_task_file_is_idempotent_when_orchestrator_dir_exists() {
        // A workspace whose `_orchestrator/` already exists (e.g. a prior
        // artifact write) must not fail — create_dir_all is idempotent.
        let dir = tempfile::tempdir().expect("tmp workspace");
        std::fs::create_dir_all(dir.path().join("_orchestrator")).expect("pre-create");
        write_task_file(dir.path(), "second task").expect("write over existing dir");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(TASK_FILE)).expect("read"),
            "second task"
        );
    }
}

// ============================================================================
// Property-based tests
// ============================================================================

#[cfg(test)]
mod proptests {
    use super::*;

    use proptest::prelude::*;

    fn arb_role() -> impl Strategy<Value = WorkerRole> {
        prop_oneof![
            Just(WorkerRole::Implementer),
            Just(WorkerRole::Adversary),
            Just(WorkerRole::Merger),
            Just(WorkerRole::Judge),
        ]
    }

    proptest! {
        /// Pane-name assembly is total over any role/issue/round and always
        /// renders a well-formed, whitespace-free `<role>-<issue>-r<round>`
        /// token with a non-empty issue segment.
        #[test]
        fn pane_name_is_total(
            role in arb_role(),
            issue in ".*",
            round in 0u32..1_000_000,
        ) {
            let name = PaneName::new(role, &issue, round).as_str();
            let round_suffix = format!("r{round}");
            prop_assert!(name.starts_with(role.as_str()));
            prop_assert!(name.ends_with(&round_suffix));
            prop_assert!(!name.contains("--"), "no empty segment: {name}");
            prop_assert!(!name.chars().any(char::is_whitespace), "no whitespace: {name}");
        }

        /// The mount matrix is a total function of the role: `.jj/` iff the role
        /// commits, the colocated `.git/` exactly when `.jj/` is (finding #1),
        /// `.crosslink/` always RO, the workspace always RW, and
        /// `.orchestrator/` never — for every role.
        #[test]
        fn mount_matrix_is_total(role in arb_role()) {
            let root = PathBuf::from("/r");
            let ws = PathBuf::from("/r/.workspace/w");
            let m = MountMatrix::for_role(role, &root, &ws);

            let expects_jj = matches!(role, WorkerRole::Implementer | WorkerRole::Merger);
            prop_assert_eq!(m.has_jj(), expects_jj, "{:?} .jj/ rule", role);
            // .git/ travels with .jj/ (colocated backend, finding #1).
            prop_assert_eq!(m.has_git(), expects_jj, "{:?} .git/ rule", role);

            // Workspace always first, RW.
            prop_assert_eq!(m.mounts()[0].mode, MountMode::ReadWrite);
            prop_assert_eq!(&m.mounts()[0].source, &ws);

            // .crosslink/ always present, RO.
            let cross = m.mounts().iter().find(|mount| {
                mount.source.file_name().is_some_and(|n| n == ".crosslink")
            });
            prop_assert!(cross.is_some());
            prop_assert_eq!(cross.unwrap().mode, MountMode::ReadOnly);

            // The colocated .git/ is bound RW when present; .orchestrator/ never.
            for mount in m.mounts() {
                if mount.source.file_name().is_some_and(|n| n == ".git") {
                    prop_assert_eq!(mount.mode, MountMode::ReadWrite);
                }
                prop_assert!(!mount.source.ends_with(".orchestrator"));
            }
        }
    }
}
