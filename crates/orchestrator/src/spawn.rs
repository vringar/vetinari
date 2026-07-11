//! Worker spawn: host a worker in a zellij pane, in a prepared jj workspace,
//! behind a `claude-sandbox` store-path pin guard (REQ-1d, REQ-4, REQ-4a,
//! REQ-5, REQ-13, AC-19, AC-27).
//!
//! This is the layer that turns a [`PreparedWorkspace`](crate::workspace) into
//! a running worker. It supports **two** worker command kinds behind one
//! abstraction ([`WorkerCommand`]):
//!
//! 1. [`WorkerCommand::Claude`] — the real path. Assembles the
//!    `claude-sandbox` + `claude` argv: `--project-dir <workspace>` for
//!    `claude-sandbox`, then after `--` the `claude` flags `--permission-mode
//!    default` (never `--dangerously-skip-permissions`, REQ-4), the per-role
//!    `--allowed-tools` allowlist, the role system prompt, and `--max-turns`
//!    (REQ-4, REQ-13). Before any such spawn the store-path pin guard (REQ-4a /
//!    AC-19) resolves `claude-sandbox` on PATH and refuses unless it is the
//!    exact pinned nix store path. This path is *not* exercised against a live
//!    Anthropic API in tests — its argv assembly is proved by pure unit tests
//!    instead.
//! 2. [`WorkerCommand::Direct`] — run an arbitrary argv (e.g.
//!    `bash tests/fixtures/fake-implementer.sh`) directly in the prepared
//!    workspace. This is the AC-11a tracer-bullet dogfood path the build pump
//!    (#15) dispatches: no live `claude`, no nested sandbox, no pin required.
//!    It is still hosted+observable in a zellij pane exactly like a real
//!    worker.
//!
//! # KNOWN LIMITATION — the per-role mount matrix is *intent*, not enforcement
//!
//! `claude-sandbox 0.1.0` manages bwrap **internally** with its own fixed mount
//! policy and accepts **no** per-role mount flags — it rejects `--bind` /
//! `--ro-bind` with `unrecognized arguments`. Therefore the per-role RO/RW
//! differentiation in [`MountMatrix`] (REQ-5 `.jj/` for Implementer/Merger
//! only, REQ-6 no `.orchestrator/`, REQ-7 `.crosslink/` RO) is **NOT currently
//! enforced** against `claude-sandbox`. The type is kept as a *documented
//! statement of intent* — what each role should be allowed to touch, still
//! useful for tests and for a future direct-`bwrap` spawn path — but its mounts
//! are **not** emitted as argv flags, because the real binary would reject
//! them. Enforcing the matrix requires either a `claude-sandbox` that accepts
//! mount flags or invoking `bwrap` directly. Tracked as follow-up.
//!
//! # Invariants made unrepresentable
//!
//! - **No stringly-typed spawn.** The role is [`WorkerRole`], the pane name is
//!   built from the typed spawn coordinates, and [`WorkerCommand`] is a closed
//!   enum — never a free-form command string.
//! - **The mount matrix is a total function of the role.** [`MountMatrix`] is
//!   built only by [`MountMatrix::for_role`]; there is no public field-setter,
//!   so an illegal per-role mount set (an Adversary with `.jj/`) cannot be
//!   *described*. (See the KNOWN LIMITATION above: describing it and enforcing
//!   it are, against `claude-sandbox 0.1.0`, two different things.)
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
//! zellij is reached only through [`vetinari_zellij_host`]. `claude-sandbox`
//! and `claude` are the two whitelisted `Command::new` targets (they have no
//! Rust library form); the pin guard's PATH resolution of `claude-sandbox`
//! goes through the standard library, not a subprocess. No
//! `jj`/`git`/`gh`/`crosslink`/`zellij` subprocess is constructed here.

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

/// The `claude-sandbox` wrapper binary — one of the two whitelisted shell-out
/// targets (AC-24), since no Rust library form exists.
pub const CLAUDE_SANDBOX_BIN: &str = "claude-sandbox";

/// The `claude` CLI — the other whitelisted shell-out target (AC-24).
pub const CLAUDE_BIN: &str = "claude";

/// The `.jj/` repository directory a worker's sandbox may see (REQ-5), relative
/// to the repository root.
pub const JJ_DIR: &str = ".jj";

/// The `.crosslink/` directory workers get a read-only bind of (REQ-7).
pub const CROSSLINK_DIR: &str = ".crosslink";

/// The `.git/` directory that is **never** bound into any worker sandbox
/// (REQ-5). Named as a constant purely so the invariant is greppable — no code
/// path ever mounts it.
pub const GIT_DIR: &str = ".git";

/// The `.orchestrator/` directory that is **never** bound into any worker
/// sandbox (REQ-6). Named for the same greppability reason as [`GIT_DIR`].
pub const ORCHESTRATOR_DIR: &str = ".orchestrator";

/// The env var the dev shell captures the resolved `claude-sandbox` nix store
/// path into (REQ-4a). The store path uniquely identifies the pinned version.
pub const SANDBOX_PIN_ENV: &str = "VDD_CLAUDE_SANDBOX_PIN";

/// The minimal set of environment variable *names* a worker is allowed to
/// inherit from the orchestrator's ambient environment. Everything else — API
/// keys, tokens, `GH_TOKEN`, the [`SANDBOX_PIN_ENV`] pin, `CROSSBRIDGE_*`
/// secrets — is scrubbed before the worker starts (env hygiene). A worker only
/// needs enough to find its interpreter (`PATH`), resolve `$HOME`-relative
/// config, and render a terminal (`TERM`); anything role-specific is passed
/// explicitly via [`WorkerCommand::Direct`]'s `env` list.
///
/// The scrub is realized by launching the worker under `env -i <ALLOWED=…>`
/// (see [`scrub_env_prefix`]): `env -i` clears the inherited environment (the
/// equivalent of [`std::process::Command::env_clear`] for a command we hand to
/// zellij rather than spawn directly), then re-sets only these names plus any
/// caller-supplied `Direct` env.
pub const WORKER_ENV_ALLOWLIST: &[&str] = &["PATH", "HOME", "TERM"];

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

/// Access mode intended for a bind mount into a worker sandbox.
///
/// Note this is *intent*, not enforcement against `claude-sandbox 0.1.0` — see
/// the module-level KNOWN LIMITATION. It maps conceptually to bwrap's
/// `--bind` / `--ro-bind`, which a future direct-`bwrap` path would emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountMode {
    /// Read-write bind (conceptually bwrap `--bind`).
    ReadWrite,
    /// Read-only bind (conceptually bwrap `--ro-bind`).
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

/// The per-role bind surface a worker sandbox *should* be given (the design's
/// mount table, REQ-5/6/7). Built *only* by [`MountMatrix::for_role`]: there is
/// no public field-setter and no other constructor, so an illegal per-role
/// mount set is unrepresentable — an [`WorkerRole::Adversary`] can never carry
/// `.jj/`, and `.git/` / `.orchestrator/` are never present for *any* role
/// because no code path adds them.
///
/// **KNOWN LIMITATION (see module docs):** this is a *statement of intent*, not
/// something enforced against `claude-sandbox 0.1.0`, which manages its own
/// bwrap mounts and rejects mount flags. It is deliberately **not** emitted as
/// argv — it exists for tests and a future direct-`bwrap` path. `has_jj`,
/// [`Mount`], and [`MountMode`] describe what each role ought to see, and the
/// role→`.jj/` decision is still validated by the unit tests below.
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
    /// | `<root>/.jj/`        | yes         | **no**    | yes    | no    |
    /// | `<root>/.crosslink/` (RO) | yes    | yes       | yes    | yes   |
    /// | `<root>/.git/`       | **no**      | **no**    | **no** | **no**|
    /// | `<root>/.orchestrator/` | **no**   | **no**    | **no** | **no**|
    ///
    /// The Implementer and Merger see `.jj/` RW (they commit via the `jj` CLI,
    /// REQ-5); the Adversary never does (it only reads a pre-rendered diff,
    /// REQ-8, and its concurrency budget assumes no `.jj/` mount, REQ-5a).
    /// Every role gets the workspace RW and `.crosslink/` RO (REQ-7). `.git/`
    /// (REQ-5) and `.orchestrator/` (REQ-6) are physically absent — no branch
    /// here binds them.
    ///
    /// **REQ-7 dependency (doc note):** the RW `.jj/` grant is only *safe*
    /// because concurrent writers to the shared `.jj/` are serialized by the
    /// orchestrator-side external allowlist + per-repo mutex (S2). Two workers
    /// mutating `.jj/` at once would corrupt the operation log; this matrix
    /// grants the mount but the S2 mutex is what makes granting it sound. If S2
    /// ever stops serializing `.jj/` writers, this RW grant becomes unsafe.
    /// (This is doubly moot today given the KNOWN LIMITATION above — the mount
    /// isn't enforced against `claude-sandbox 0.1.0` at all — but the safety
    /// dependency is recorded here for the future direct-`bwrap` path.)
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
        // `.jj/` RW for the roles that commit; never for the Adversary or the
        // (MVP-stub) Judge. This is the one role-conditional bind, and the
        // *only* place `.jj/` is ever added.
        if role_gets_jj(role) {
            mounts.push(Mount {
                source: root.join(JJ_DIR),
                mode: MountMode::ReadWrite,
            });
        }
        // NOTE: `.git/` (REQ-5) and `.orchestrator/` (REQ-6) are deliberately
        // NOT added by any branch. Their absence is the invariant.
        MountMatrix { mounts }
    }

    /// The mounts in a stable order (workspace, `.crosslink/`, then `.jj/` if
    /// present).
    pub fn mounts(&self) -> &[Mount] {
        &self.mounts
    }

    /// Whether this matrix binds `.jj/` (true for Implementer/Merger only).
    pub fn has_jj(&self) -> bool {
        self.mounts
            .iter()
            .any(|m| m.source.file_name().is_some_and(|n| n == JJ_DIR))
    }
}

/// Build the `env -i KEY=VALUE …` prefix that scrubs the orchestrator's
/// ambient environment down to a minimal allowlist before the worker runs.
///
/// The worker command is handed to zellij, which spawns it inheriting the
/// zellij server's environment (the orchestrator's full ambient env — API
/// keys, tokens, the [`SANDBOX_PIN_ENV`] pin). We cannot call
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
fn scrub_env_prefix(extra: &[(String, String)]) -> Vec<String> {
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
    /// / AC-11a dogfood path). No `claude-sandbox`, no nested sandbox, no pin
    /// check. Still hosted in a zellij pane so it is observable like a real
    /// worker.
    Direct {
        /// The program plus its arguments (must be non-empty). The pane runs
        /// this verbatim in the workspace cwd.
        argv: Vec<String>,
        /// Extra environment applied to the pane (zellij prefixes `env K=V …`).
        env: Vec<(String, String)>,
    },
    /// Spawn a real `claude` worker inside `claude-sandbox` with the per-role
    /// mount matrix, allowlist, prompt, and turn cap (REQ-4, REQ-5, REQ-13).
    /// The version-pin guard (REQ-4a) runs before this is launched.
    Claude(ClaudeSpawn),
}

/// The fully-specified inputs of a real `claude` spawn. Held in its own struct
/// so [`ClaudeSpawn::to_argv`] can be a pure, unit-testable function of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeSpawn {
    /// The worker role (drives the allowlist, prompt, and — via
    /// [`MountMatrix::for_role`] — the mount surface).
    pub role: WorkerRole,
    /// The task prompt, delivered to `claude` on stdin (REQ-8).
    pub task: String,
    /// The per-role `--allowed-tools` value (REQ-4, REQ-5). A closed string the
    /// caller derives from the role's allowlist.
    pub allowlist: String,
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
        system_prompt: impl Into<String>,
        max_turns: u32,
    ) -> Self {
        WorkerCommand::Claude(ClaudeSpawn {
            role,
            task: task.into(),
            allowlist: allowlist.into(),
            system_prompt: system_prompt.into(),
            max_turns,
            mounts: MountMatrix::for_role(role, root, workspace),
        })
    }
}

impl ClaudeSpawn {
    /// Assemble the full `claude-sandbox … -- claude …` argv as a pure function
    /// — nothing is spawned, so this is unit-testable in isolation (the
    /// live-claude path is never exercised in tests, so its correctness is
    /// proved *here*).
    ///
    /// The shape — **only flags the real `claude-sandbox 0.1.0` accepts**:
    ///
    /// ```text
    /// claude-sandbox --project-dir <ws> \
    ///   -- claude --permission-mode default \
    ///      --allowed-tools <allowlist> \
    ///      --append-system-prompt <prompt> \
    ///      --max-turns <n>
    /// ```
    ///
    /// No `--bind` / `--ro-bind` flags are emitted: `claude-sandbox 0.1.0`
    /// rejects them (`unrecognized arguments`) and enforces its own bwrap mount
    /// policy internally, so the [`MountMatrix`] is intent-only (see the module
    /// KNOWN LIMITATION). The `-- claude …` suffix is **required**: without it,
    /// `claude-sandbox`'s default command is `claude
    /// --dangerously-skip-permissions`, which REQ-4 forbids — so we always spell
    /// out `claude --permission-mode default` ourselves.
    ///
    /// The task prompt is delivered on stdin, not argv (REQ-8), so it is not in
    /// this vector. `--permission-mode default` and the *absence* of
    /// `--dangerously-skip-permissions` are hard-coded (REQ-4): there is no
    /// argument that could turn them off.
    pub fn to_argv(&self, workspace: &Path) -> Vec<String> {
        let ws = workspace.to_string_lossy().into_owned();
        vec![
            CLAUDE_SANDBOX_BIN.to_owned(),
            "--project-dir".to_owned(),
            ws,
            "--".to_owned(),
            CLAUDE_BIN.to_owned(),
            "--permission-mode".to_owned(),
            "default".to_owned(),
            "--allowed-tools".to_owned(),
            self.allowlist.clone(),
            "--append-system-prompt".to_owned(),
            self.system_prompt.clone(),
            "--max-turns".to_owned(),
            self.max_turns.to_string(),
        ]
    }
}

// ============================================================================
// Store-path pin guard (REQ-4a / AC-19)
// ============================================================================

/// The `claude-sandbox` **store-path** pin the orchestrator was configured with
/// (REQ-4a). The dev shell captures the resolved nix store path — e.g.
/// `/nix/store/<hash>-claude-sandbox-0.1.0/bin/claude-sandbox` — into
/// [`SANDBOX_PIN_ENV`] at shell entry. Because a nix store path is
/// content-addressed, that path *is* the exact pinned build: two different
/// versions live at two different store paths. So verification is **path
/// identity**, not a version string.
///
/// [`verify`](Self::verify) resolves `claude-sandbox` on `PATH`, canonicalizes
/// it to its real target, and requires it to **equal** the pinned path exactly.
/// This fails closed:
///
/// - An empty/unset pin ⇒ error (no accept-all fallback).
/// - `claude-sandbox` not resolvable on `PATH` ⇒ error.
/// - A shim at a *different* path (e.g. a PATH-injected fake) ⇒ mismatch error,
///   even if it names itself `claude-sandbox`.
///
/// A newtype over the pinned path so a real spawn can only be guarded, never
/// compared against a bare `&str` a caller might forget to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPin {
    expected: String,
}

impl SandboxPin {
    /// The pin the orchestrator was configured with (the resolved
    /// [`SANDBOX_PIN_ENV`] store path).
    pub fn new(expected: impl Into<String>) -> Self {
        SandboxPin {
            expected: expected.into(),
        }
    }

    /// Read the pin from [`SANDBOX_PIN_ENV`]. Returns
    /// [`SpawnError::ClaudeSandboxMissing`] if the variable is unset or empty —
    /// a real spawn cannot proceed without a pin (REQ-4a, fail-closed).
    pub fn from_env() -> Result<Self, SpawnError> {
        match std::env::var(SANDBOX_PIN_ENV) {
            Ok(v) if !v.is_empty() => Ok(SandboxPin::new(v)),
            _ => Err(SpawnError::ClaudeSandboxMissing {
                searched: SANDBOX_PIN_ENV.to_owned(),
            }),
        }
    }

    /// The expected pinned store path.
    pub fn expected(&self) -> &str {
        &self.expected
    }

    /// Resolve `claude-sandbox` on `PATH` and confirm it is the exact pinned
    /// store path (REQ-4a / AC-19).
    ///
    /// - Empty pin ⇒ [`SpawnError::ClaudeSandboxMissing`] (fail-closed; there is
    ///   no accept-all).
    /// - `claude-sandbox` not found on `PATH`, or unreadable ⇒
    ///   [`SpawnError::ClaudeSandboxMissing`].
    /// - Resolved real path ≠ pinned path ⇒
    ///   [`SpawnError::ClaudeSandboxVersionMismatch`] (the AC-19 refusal).
    ///
    /// The comparison canonicalizes both sides with [`std::fs::canonicalize`]
    /// (resolving symlinks such as the `~/.nix-profile/bin/claude-sandbox`
    /// profile link down to the underlying `/nix/store/…` file) so identity is
    /// judged on the real store path, not on which symlink `PATH` happened to
    /// hit.
    pub fn verify(&self) -> Result<(), SpawnError> {
        if self.expected.is_empty() {
            // Fail closed: an unconfigured pin must never accept whatever
            // `claude-sandbox` happens to be first on PATH.
            return Err(SpawnError::ClaudeSandboxMissing {
                searched: SANDBOX_PIN_ENV.to_owned(),
            });
        }

        let path_env = std::env::var("PATH").unwrap_or_default();
        let resolved = resolve_on_path(CLAUDE_SANDBOX_BIN, &path_env).ok_or_else(|| {
            SpawnError::ClaudeSandboxMissing {
                searched: path_env.clone(),
            }
        })?;

        // Canonicalize both sides so we compare real store paths, not the
        // profile symlink vs. its target.
        let resolved_real =
            std::fs::canonicalize(&resolved).map_err(|_| SpawnError::ClaudeSandboxMissing {
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
            Err(SpawnError::ClaudeSandboxVersionMismatch {
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
    /// ([`SandboxPin::from_env`] / [`SANDBOX_PIN_ENV`]) — the production
    /// constructor. Fails closed with [`SpawnError::ClaudeSandboxMissing`] if
    /// the pin is unset, so an orchestrator cannot start real `claude` spawns
    /// without a configured pin (REQ-4a). Tests that don't exercise the real
    /// path use [`Spawner::new`] with an explicit pin instead.
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
    /// runs **first**: if the `claude-sandbox` resolved on PATH is not the exact
    /// pinned nix store path, [`SpawnError::ClaudeSandboxVersionMismatch`] is
    /// returned and *no* pane is created. For [`WorkerCommand::Direct`] the
    /// guard is skipped (the dogfood path).
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
                // REQ-4a / AC-19: refuse to spawn on a pin mismatch, BEFORE the
                // pane exists.
                self.pin.verify()?;
                (spawn.to_argv(workspace.path()), Vec::new())
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
        // Workspace RW + .jj/ RW + .crosslink/ RO.
        assert!(m.has_jj(), "Implementer must see .jj/");
        assert_eq!(mode_of(&m, ".jj"), Some(MountMode::ReadWrite));
        assert_eq!(mode_of(&m, ".crosslink"), Some(MountMode::ReadOnly));
        // The workspace dir is bound RW.
        assert_eq!(
            m.mounts()[0],
            Mount {
                source: ws(),
                mode: MountMode::ReadWrite
            }
        );
        // Never .git/ or .orchestrator/.
        let srcs = sources(&m);
        assert!(!srcs.iter().any(|s| s.ends_with(".git")), "no .git/ mount");
        assert!(
            !srcs.iter().any(|s| s.ends_with(".orchestrator")),
            "no .orchestrator/ mount"
        );
    }

    #[test]
    fn adversary_never_gets_jj() {
        let m = MountMatrix::for_role(WorkerRole::Adversary, &root(), &ws());
        assert!(!m.has_jj(), "Adversary must NEVER see .jj/ (REQ-5, REQ-5a)");
        // Still has workspace RW + .crosslink/ RO.
        assert_eq!(mode_of(&m, ".crosslink"), Some(MountMode::ReadOnly));
        assert_eq!(m.mounts()[0].mode, MountMode::ReadWrite);
        let srcs = sources(&m);
        assert!(!srcs.iter().any(|s| s.ends_with(".git")));
        assert!(!srcs.iter().any(|s| s.ends_with(".orchestrator")));
    }

    #[test]
    fn merger_matrix_matches_implementer_binds() {
        let imp = MountMatrix::for_role(WorkerRole::Implementer, &root(), &ws());
        let mrg = MountMatrix::for_role(WorkerRole::Merger, &root(), &ws());
        // Merger sees the same bind surface as the Implementer (.jj/ RW).
        assert!(mrg.has_jj());
        assert_eq!(imp.mounts(), mrg.mounts());
    }

    #[test]
    fn no_role_ever_mounts_git_or_orchestrator() {
        for role in [
            WorkerRole::Implementer,
            WorkerRole::Adversary,
            WorkerRole::Merger,
            WorkerRole::Judge,
        ] {
            let m = MountMatrix::for_role(role, &root(), &ws());
            for mount in m.mounts() {
                assert!(
                    !mount.source.ends_with(".git"),
                    "{role:?} must never mount .git/"
                );
                assert!(
                    !mount.source.ends_with(".orchestrator"),
                    "{role:?} must never mount .orchestrator/"
                );
            }
        }
    }

    // --- ClaudeSpawn::to_argv (pure assembly; REQ-4, REQ-13) ----------------

    fn implementer_spawn() -> ClaudeSpawn {
        match WorkerCommand::claude(
            WorkerRole::Implementer,
            &root(),
            &ws(),
            "do the thing",
            "Bash(jj describe),Read,Edit,Write",
            "You are the Implementer.",
            80,
        ) {
            WorkerCommand::Claude(s) => s,
            _ => unreachable!(),
        }
    }

    #[test]
    fn claude_argv_has_required_flags_and_no_dangerous_skip() {
        let argv = implementer_spawn().to_argv(&ws());
        assert_eq!(argv[0], CLAUDE_SANDBOX_BIN);
        // --project-dir <ws> present.
        let pd = argv.iter().position(|a| a == "--project-dir").expect("pd");
        assert_eq!(argv[pd + 1], ws().to_string_lossy());
        // The `--` separator, then `claude`.
        let sep = argv.iter().position(|a| a == "--").expect("separator");
        assert_eq!(argv[sep + 1], CLAUDE_BIN);
        // REQ-4: permission mode default, allowlist, prompt, max-turns.
        assert!(argv
            .windows(2)
            .any(|w| w == ["--permission-mode", "default"]));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--allowed-tools" && w[1] == "Bash(jj describe),Read,Edit,Write"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--append-system-prompt" && w[1] == "You are the Implementer."));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--max-turns" && w[1] == "80"));
        // REQ-4: NEVER --dangerously-skip-permissions.
        assert!(
            !argv.iter().any(|a| a == "--dangerously-skip-permissions"),
            "REQ-4: must never pass --dangerously-skip-permissions"
        );
        // The real claude-sandbox 0.1.0 REJECTS mount flags — none must appear.
        assert!(
            !argv.iter().any(|a| a == "--bind" || a == "--ro-bind"),
            "claude-sandbox 0.1.0 rejects --bind/--ro-bind; none must be emitted"
        );
        // `claude-sandbox` sees only --project-dir <ws> before the `--`.
        assert_eq!(
            &argv[..sep],
            &[CLAUDE_SANDBOX_BIN, "--project-dir", &ws().to_string_lossy()]
        );
        // The task goes on stdin, not argv.
        assert!(!argv.iter().any(|a| a == "do the thing"));
    }

    #[test]
    fn adversary_argv_carries_no_jj_bind() {
        let spawn = match WorkerCommand::claude(
            WorkerRole::Adversary,
            &root(),
            &ws(),
            "review",
            "Read",
            "You are the Adversary.",
            40,
        ) {
            WorkerCommand::Claude(s) => s,
            _ => unreachable!(),
        };
        let argv = spawn.to_argv(&ws());
        // No `.jj` path appears anywhere in the assembled argv.
        assert!(
            !argv.iter().any(|a| a.ends_with(".jj")),
            "Adversary argv must not bind .jj/"
        );
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--max-turns" && w[1] == "40"));
    }

    // --- SandboxPin: store-path identity (fail-closed) ----------------------

    #[test]
    fn empty_pin_fails_closed() {
        // An unset/empty pin must NEVER accept-all — it errors before even
        // resolving anything on PATH.
        let err = SandboxPin::new("").verify().unwrap_err();
        assert!(
            matches!(err, SpawnError::ClaudeSandboxMissing { .. }),
            "empty pin must fail closed, got {err:?}"
        );
    }

    #[test]
    fn resolve_on_path_finds_first_hit() {
        let dir = tempfile::tempdir().expect("tmp");
        let bin = dir.path().join("claude-sandbox");
        std::fs::write(&bin, "").expect("write");
        let path_env = dir.path().to_string_lossy().into_owned();
        assert_eq!(
            resolve_on_path("claude-sandbox", &path_env).as_deref(),
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
        /// commits, `.crosslink/` always RO, the workspace always RW, and
        /// `.git/`/`.orchestrator/` never — for every role.
        #[test]
        fn mount_matrix_is_total(role in arb_role()) {
            let root = PathBuf::from("/r");
            let ws = PathBuf::from("/r/.workspace/w");
            let m = MountMatrix::for_role(role, &root, &ws);

            let expects_jj = matches!(role, WorkerRole::Implementer | WorkerRole::Merger);
            prop_assert_eq!(m.has_jj(), expects_jj, "{:?} .jj/ rule", role);

            // Workspace always first, RW.
            prop_assert_eq!(m.mounts()[0].mode, MountMode::ReadWrite);
            prop_assert_eq!(&m.mounts()[0].source, &ws);

            // .crosslink/ always present, RO.
            let cross = m.mounts().iter().find(|mount| {
                mount.source.file_name().is_some_and(|n| n == ".crosslink")
            });
            prop_assert!(cross.is_some());
            prop_assert_eq!(cross.unwrap().mode, MountMode::ReadOnly);

            // Never .git/ or .orchestrator/.
            for mount in m.mounts() {
                prop_assert!(!mount.source.ends_with(".git"));
                prop_assert!(!mount.source.ends_with(".orchestrator"));
            }
        }
    }
}
