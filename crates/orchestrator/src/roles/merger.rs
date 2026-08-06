//! The **Merger** role: allowlist, deny list, system prompt, turn cap, the
//! [`WorkerCommand`] builder, and the orchestrator-side pre-rendering of its
//! `conflict.md` input (REQ-19, L4).
//!
//! When the orchestrator's local-mode landing rebases an issue's change onto
//! `main` and that rebase **conflicts**, the change is not parked for a human
//! immediately (that is the last resort). Instead the orchestrator spawns a
//! Merger worker in a fresh jj workspace **already checked out in the conflicted
//! state** (its working copy carries the materialized conflict markers), and the
//! Merger's one job is to resolve every marker to a correct merge. On the
//! Merger's completion the orchestrator re-runs static QA on the merged tree and,
//! only if that passes and no conflicts remain, retries the fast-forward landing
//! ONCE (REQ-19; the pump owns that dance). Any failure — missing DONE, an
//! unresolved conflict, post-merge QA failure, or a still-not-fast-forward retry
//! — falls back to `phase:awaiting-human-merge`.
//!
//! # Mount surface (REQ-5 amendment, finding #1)
//!
//! Like the Implementer, the Merger commits through `jj` on the jj-git-colocated
//! repo, so its sandbox binds the repository `.jj/` **and** `.git/` read-write
//! ([`MountMatrix::for_role`](crate::spawn::MountMatrix::for_role) already grants
//! both to [`WorkerRole::Merger`]). It never sees `.orchestrator/`.
//!
//! # Allowlist — narrower than the Implementer's on purpose
//!
//! The Merger is a *conflict resolver*, not an author. Its allowlist adds the jj
//! conflict-resolution verbs (`jj resolve`, `jj restore`) plus the read-only
//! inspection verbs it needs to see the conflict (`jj status`, `jj diff`), and
//! the file-edit tools (`Read`/`Edit`/`Write`) to rewrite the conflicted files.
//! It deliberately does **not** carry the history-rewriting verbs, `git`, or a
//! blanket bash — the same guardrail-not-a-cage posture as the other roles (see
//! the threat-model block in [`crate::roles`]): what actually keeps a bad merge
//! off `main` is the orchestrator-side post-merge QA gate and the
//! fast-forward-guarded retry, never the allowlist.
//!
//! ## Why the resolution needs no explicit commit verb
//!
//! REQ-19's wording is "the resolution committed via `jj describe`". In jj the
//! working copy **is** a commit: editing the conflicted files to remove the
//! markers and then running any snapshotting jj command (`jj status`, `jj diff`,
//! `jj resolve` — all allowlisted) folds the resolved tree into the workspace's
//! working-copy commit, which the orchestrator then reads back through `jj_api`.
//! So the narrowed allowlist omits `jj describe` (and the history-rewriting
//! `jj squash`/`split`, blocked for the REQ-5 reasons) while still delivering a
//! committed, conflict-free resolution the orchestrator can land.

use std::path::{Path, PathBuf};

use vetinari_error::SpawnError;

use crate::artifacts::ARTIFACT_DIR;
use crate::spawn::WorkerCommand;
use crate::state::WorkerRole;

/// The Merger's default `--max-turns` cap (REQ-13 `max_turns_merger`, default
/// 30). A worker hitting its turn cap is treated like any other crash (no DONE
/// sentinel → the pump falls back to `phase:awaiting-human-merge`).
pub const DEFAULT_MAX_TURNS: u32 = 30;

/// The Merger's default turn cap, [`DEFAULT_MAX_TURNS`]. A function so a call
/// site reads symmetrically with the other role knobs ([`allowed_tools`] etc.).
pub fn max_turns() -> u32 {
    DEFAULT_MAX_TURNS
}

/// The pre-rendered `conflict.md` input filename, relative to [`ARTIFACT_DIR`].
/// The orchestrator writes it before the spawn; the Merger reads it first.
pub const CONFLICT_FILE: &str = "conflict.md";

/// The Merger's freeform output artifact (REQ-19): "files resolved, strategy
/// used", relative to [`ARTIFACT_DIR`]. Posted as a `--kind resolution` comment
/// post-phase in a later iteration; for the MVP it is DONE-attested and read
/// back for the audit trail.
pub const MERGE_RESULT_FILE: &str = "merge_result.md";

/// The Merger's `--allowed-tools` tokens, as a **structured list** joined once
/// by [`allowed_tools`] — never a hand-typed blob, so the set is auditable
/// token-by-token and a new entry is a deliberate line here.
///
/// A **guardrail, not a cage** (see [`crate::roles`]). It contains, and can only
/// ever contain, what is listed:
///
/// - The jj **conflict-resolution** verbs `jj resolve` / `jj restore`, plus the
///   read-only inspection verbs `jj status` / `jj diff` — enough to see the
///   conflict and resolve it, nothing that rewrites history or the op log.
/// - `Read` / `Edit` / `Write` — read `conflict.md` + the conflicted files, edit
///   those files to a correct merge, and write `merge_result.md` + the DONE
///   sentinel.
/// - `Bash(cargo build:*)` / `Bash(cargo test:*)` — the Merger MAY self-verify
///   its merge compiles/passes before DONE (the prompt invites it); the
///   authoritative gate is still the orchestrator-side post-merge QA (REQ-19).
/// - `Bash(sha256sum:*)` — the DONE manifest's per-artifact hash (REQ-3b).
///
/// It deliberately omits, and there is simply no token for: `git`, `jj git
/// push`/`fetch`, the history/op-log surgery verbs (`abandon`, `op`, `rebase`,
/// `squash`, `split`, `edit`, `workspace`), the bookmark/commit-authoring verbs
/// the orchestrator owns (`bookmark`, `new`, `commit`), `jj describe` (unneeded —
/// the working copy auto-snapshots, see the module docs), and a blanket
/// `Bash(*)`. The known-dangerous of these are *also* named in
/// [`DISALLOWED_TOOLS`] for a clean refusal.
pub const ALLOWED_TOOLS: &[&str] = &[
    // jj conflict-resolution + read-only inspection — the Merger's VCS surface.
    "Bash(jj resolve:*)",
    "Bash(jj restore:*)",
    "Bash(jj status:*)",
    "Bash(jj diff:*)",
    // Edit the conflicted files; read the pre-rendered conflict.md; write the
    // merge_result + DONE. `Write` creates files + parent dirs.
    "Read",
    "Edit",
    "Write",
    // Optional self-verification of the merge before DONE (the prompt invites
    // it); the orchestrator-side post-merge QA is the authoritative gate.
    "Bash(cargo build:*)",
    "Bash(cargo test:*)",
    // Artifact-contract helper (REQ-3b): the DONE manifest's per-artifact hash.
    "Bash(sha256sum:*)",
];

/// The `--allowed-tools` value: [`ALLOWED_TOOLS`] joined by `,`. Built from the
/// structured list once, so the wire value and the auditable token list can
/// never drift.
pub fn allowed_tools() -> String {
    ALLOWED_TOOLS.join(",")
}

/// The Merger's `--disallowed-tools` tokens: a clean-refusal deny list for the
/// VCS verbs it must never reach, joined once by [`disallowed_tools`].
///
/// Because `--permission-mode default` *asks* (rather than denies) for an
/// unlisted tool — and a headless worker has no one to answer, so the call
/// wedges until the pump's timeout (see [`crate::roles`]) — the known-dangerous
/// verbs get an explicit `--disallowed-tools` entry so `claude` refuses them
/// outright. The Merger DOES use some jj (resolve/restore/status/diff), so — like
/// the Implementer, unlike the blanket-jj-deny Adversary — the blocked jj verbs
/// are enumerated rather than blanket-denied.
pub const DISALLOWED_TOOLS: &[&str] = &[
    // Never reach a remote — the orchestrator owns landing (REQ-5, REQ-17).
    "Bash(git:*)",
    "Bash(jj git push:*)",
    "Bash(jj git fetch:*)",
    // Never rewrite history or the global operation log (REQ-5 BLOCKED).
    "Bash(jj abandon:*)",
    "Bash(jj op:*)",
    "Bash(jj rebase:*)",
    "Bash(jj squash:*)",
    "Bash(jj split:*)",
    "Bash(jj edit:*)",
    "Bash(jj workspace:*)",
    // The orchestrator owns landing and the `main` bookmark — a Merger that
    // reaches for these (esp. `jj bookmark set main`) must be cleanly refused,
    // not left to wedge on the permission-ask until the pump's timeout. Moving a
    // bookmark, starting a new change, or committing are all outside the
    // resolve/restore/inspect surface the Merger needs (the FF-guard still
    // governs `main` regardless — this only honors the deny-list policy).
    "Bash(jj bookmark:*)",
    "Bash(jj new:*)",
    "Bash(jj commit:*)",
];

/// The `--disallowed-tools` value: [`DISALLOWED_TOOLS`] joined by `,`. Built from
/// the structured list once, so the wire value and the auditable token list can
/// never drift.
pub fn disallowed_tools() -> String {
    DISALLOWED_TOOLS.join(",")
}

/// The Merger role system prompt, passed via `--append-system-prompt`.
///
/// Encodes the Merger contract: read `conflict.md`, resolve every conflict marker
/// to a correct merge that preserves BOTH sides' intent without adding features
/// or changing logic, optionally self-verify, then write `merge_result.md` and
/// the `_orchestrator/DONE` sentinel LAST (REQ-3b, REQ-19). The spawn layer
/// appends its own fixed "read your task file" instruction after this (REQ-8).
pub fn system_prompt() -> String {
    SYSTEM_PROMPT.to_owned()
}

/// The literal Merger system prompt (see [`system_prompt`]).
const SYSTEM_PROMPT: &str = "\
You are the Merger, an autonomous conflict-resolution worker in the vetinari VDD \
orchestrator. You run with a fresh context. Your jj workspace is ALREADY checked \
out in the conflicted state: the files carry conflict markers from a rebase that \
could not apply cleanly.

Read `_orchestrator/conflict.md` at the root of your working directory first — it \
names the failing operation, the target the change was being landed onto, and \
the change under merge. Then run `jj status` / `jj diff` to see exactly which \
files conflict.

You are resolving a VCS merge conflict. Resolve every conflict marker \
(`<<<<<<<`, `=======`, `>>>>>>>`) to a correct, compiling merge that preserves \
BOTH the incoming change's intent AND the target's. Do NOT add features, do NOT \
change logic, do NOT resolve by simply discarding one side — merge them. Run the \
tests if available (`cargo build` / `cargo test`) to check your merge compiles \
and passes before you finish. Remove EVERY conflict marker; a file that still \
contains one is an unresolved conflict.

When the resolution is complete, produce your artifacts under `_orchestrator/`, \
in this order and with DONE strictly LAST:

1. Write `_orchestrator/merge_result.md` describing which files you resolved and \
   the merge strategy you used.
2. Write `_orchestrator/DONE` as your VERY LAST filesystem operation. Its content \
   is JSON: {\"exit_status\":\"success\",\"artifacts\":[{\"path\":\"_orchestrator/merge_result.md\",\"sha256\":\"<sha256 of merge_result.md>\"}]}. \
   Use `sha256sum` to compute the hash. If you could not resolve the conflict, \
   set \"exit_status\":\"error\" instead.

Constraints: stay within your workspace directory. Never read or write the \
orchestrator-private `.orchestrator/` directory (note the leading dot — it is \
distinct from the `_orchestrator/` inputs/outputs above). Never rebase, squash, \
push, or open a pull request — the orchestrator retries the landing for you once \
your resolution is done.";

// ============================================================================
// Input pre-rendering (REQ-19)
// ============================================================================

/// The context the orchestrator renders into a Merger workspace's `conflict.md`
/// (REQ-19): the failing operation, the target it was landing onto, the change
/// under merge, and the conflicted commit the workspace is checked out on.
///
/// Grouped in a struct rather than a long argument list so the call site reads
/// by field and a new input is a named addition, not a positional footgun.
#[derive(Debug, Clone, Copy)]
pub struct ConflictContext<'a> {
    /// The failing landing operation, e.g. `"rebase onto main"`.
    pub operation: &'a str,
    /// The bookmark the change was being landed onto (typically `main`).
    pub target_bookmark: &'a str,
    /// The commit the target bookmark points at.
    pub target_commit: &'a str,
    /// Revset naming the change under merge (the issue's committed change).
    pub change_revset: &'a str,
    /// The conflicted commit the Merger workspace is checked out on (the rebase
    /// result whose tree carries the markers).
    pub conflicted_commit: &'a str,
}

/// Pre-render the Merger's `conflict.md` input into `<workspace>/_orchestrator/`
/// (REQ-19), BEFORE the Merger spawn.
///
/// On success returns a [`RenderedMergerInputs`] token — the typed proof the
/// input exists, which [`worker_command`] requires to spawn the Merger, so the
/// spawn cannot outrun the pre-render (mirrors the Adversary's
/// [`RenderedAdversaryInputs`](crate::roles::adversary::RenderedAdversaryInputs)).
/// A filesystem write failure surfaces as [`SpawnError::Io`] carrying the path.
pub fn render_conflict_input(
    workspace: &Path,
    ctx: &ConflictContext<'_>,
) -> Result<RenderedMergerInputs, SpawnError> {
    let dir = workspace.join(ARTIFACT_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| SpawnError::io(&dir, e))?;
    let path = dir.join(CONFLICT_FILE);
    std::fs::write(&path, render_conflict_md(ctx)).map_err(|e| SpawnError::io(&path, e))?;
    Ok(RenderedMergerInputs {
        workspace: workspace.to_path_buf(),
    })
}

/// Render the `conflict.md` body from the context. Pure and total — no I/O.
fn render_conflict_md(ctx: &ConflictContext<'_>) -> String {
    format!(
        "# Rebase conflict to resolve\n\
         \n\
         The landing operation `{operation}` could not apply cleanly. Your \
         workspace is checked out in the conflicted state.\n\
         \n\
         - **Operation:** {operation}\n\
         - **Target bookmark:** `{bookmark}` (`{target}`)\n\
         - **Change under merge:** `{change}`\n\
         - **Conflicted commit (your checkout):** `{conflicted}`\n\
         \n\
         Run `jj status` and `jj diff` to see the conflicted files. Resolve every \
         conflict marker to a correct merge that preserves both the change's \
         intent and the target's, then write `_orchestrator/merge_result.md` and \
         `_orchestrator/DONE` (last).\n",
        operation = ctx.operation,
        bookmark = ctx.target_bookmark,
        target = ctx.target_commit,
        change = ctx.change_revset,
        conflicted = ctx.conflicted_commit,
    )
}

/// Typed proof that [`render_conflict_input`] populated a Merger workspace's
/// `_orchestrator/conflict.md` — the render-side mirror of the Adversary's
/// [`RenderedAdversaryInputs`](crate::roles::adversary::RenderedAdversaryInputs).
///
/// [`worker_command`] takes one of these instead of a bare workspace path, so a
/// Merger cannot be spawned into a workspace whose conflict input was never
/// rendered. Its only constructor is [`render_conflict_input`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedMergerInputs {
    workspace: PathBuf,
}

impl RenderedMergerInputs {
    /// The workspace whose `conflict.md` input was pre-rendered.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

/// Build the Merger [`WorkerCommand::Claude`] for `task`, run in the pre-rendered
/// `rendered` workspace under the repository `root`, capped at `max_turns`.
///
/// A thin wrapper over [`WorkerCommand::claude`] that pins the role to
/// [`WorkerRole::Merger`] and supplies this module's [`allowed_tools`],
/// [`disallowed_tools`], and [`system_prompt`] — the caller only chooses the task
/// and the (config-derived) turn cap, so the security-critical allowlist, deny
/// list, and prompt cannot be forgotten or overridden at a call site. The derived
/// [`MountMatrix`](crate::spawn::MountMatrix) gives the Merger the repository
/// `.jj/` + `.git/` RW (like the Implementer, finding #1).
pub fn worker_command(
    root: &Path,
    rendered: &RenderedMergerInputs,
    task: impl Into<String>,
    max_turns: u32,
) -> WorkerCommand {
    WorkerCommand::claude(
        WorkerRole::Merger,
        root,
        rendered.workspace(),
        task,
        allowed_tools(),
        disallowed_tools(),
        system_prompt(),
        max_turns,
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spawn::{SandboxHost, WorkerCommand};
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from("/repo")
    }

    fn ws() -> PathBuf {
        PathBuf::from("/repo/.workspace/landing-42-r0-a1b2c3d4")
    }

    /// A render token for [`ws`] — stands in for a real [`render_conflict_input`]
    /// call so the pure builder tests need no filesystem. Legal here because
    /// these unit tests are a child module of the one that defines the token's
    /// private field.
    fn rendered() -> RenderedMergerInputs {
        RenderedMergerInputs { workspace: ws() }
    }

    /// The jj conflict-resolution + inspection verbs the Merger must permit.
    const ALLOWED_JJ: &[&str] = &["jj resolve", "jj restore", "jj status", "jj diff"];

    /// Tokens that must NEVER appear anywhere in the Merger allowlist: the
    /// history-rewriting verbs, git, describe (unneeded), and the blanket bash.
    const FORBIDDEN: &[&str] = &[
        "git",
        "jj git push",
        "jj git fetch",
        "jj abandon",
        "jj op",
        "jj rebase",
        "jj squash",
        "jj split",
        "jj edit",
        "jj workspace",
        "jj describe",
        "Bash(*)",
    ];

    #[test]
    fn allowlist_permits_conflict_resolution_and_edit_tools() {
        let a = allowed_tools();
        for verb in ALLOWED_JJ {
            assert!(a.contains(verb), "allowlist must permit `{verb}`: {a}");
        }
        for tool in [
            "Read",
            "Edit",
            "Write",
            "cargo build",
            "cargo test",
            "sha256sum",
        ] {
            assert!(a.contains(tool), "allowlist must permit `{tool}`: {a}");
        }
    }

    #[test]
    fn allowlist_excludes_every_forbidden_token() {
        let a = allowed_tools();
        for bad in FORBIDDEN {
            assert!(
                !a.contains(bad),
                "Merger allowlist must NOT contain `{bad}`: {a}"
            );
        }
    }

    #[test]
    fn allowlist_is_the_structured_list_joined_once() {
        assert_eq!(allowed_tools(), ALLOWED_TOOLS.join(","));
        // Every jj token is a `:*` prefix rule (a bare `Bash(jj)` would wildcard
        // all jj verbs — that must not happen).
        for tok in ALLOWED_TOOLS {
            if tok.starts_with("Bash(jj ") {
                assert!(
                    tok.ends_with(":*)"),
                    "jj token must be a prefix rule: {tok}"
                );
            }
        }
    }

    #[test]
    fn deny_list_names_the_known_dangerous_verbs() {
        let d = disallowed_tools();
        for verb in [
            "Bash(git:*)",
            "Bash(jj git push:*)",
            "Bash(jj rebase:*)",
            "Bash(jj squash:*)",
            "Bash(jj workspace:*)",
            // The orchestrator owns the `main` bookmark + landing (F4): a Merger
            // reaching for these must be cleanly refused, not left to wedge on the
            // permission-ask until timeout.
            "Bash(jj bookmark:*)",
            "Bash(jj new:*)",
            "Bash(jj commit:*)",
        ] {
            assert!(d.contains(verb), "deny list must name `{verb}`: {d}");
        }
        assert_eq!(disallowed_tools(), DISALLOWED_TOOLS.join(","));
    }

    #[test]
    fn max_turns_default_is_30() {
        assert_eq!(DEFAULT_MAX_TURNS, 30);
        assert_eq!(max_turns(), 30);
    }

    #[test]
    fn system_prompt_states_the_merge_contract() {
        let p = system_prompt();
        assert!(p.contains("_orchestrator/conflict.md"), "reads conflict.md");
        assert!(
            p.contains("_orchestrator/merge_result.md"),
            "writes merge_result.md"
        );
        assert!(p.contains("_orchestrator/DONE"), "writes DONE");
        assert!(p.to_lowercase().contains("last"), "DONE written LAST");
        assert!(
            p.contains("conflict marker") || p.contains("<<<<<<<"),
            "explains conflict markers"
        );
        // Isolation reminders.
        assert!(p.contains(".orchestrator/"), "warns off the private dir");
        assert!(
            p.to_lowercase().contains("push"),
            "forbids pushing / re-landing"
        );
    }

    #[test]
    fn render_conflict_md_names_the_operation_and_target() {
        let ctx = ConflictContext {
            operation: "rebase onto main",
            target_bookmark: "main",
            target_commit: "deadbeef",
            change_revset: "abc123",
            conflicted_commit: "cafe0000",
        };
        let md = render_conflict_md(&ctx);
        assert!(md.contains("rebase onto main"), "{md}");
        assert!(md.contains("main"), "{md}");
        assert!(md.contains("deadbeef"), "target commit: {md}");
        assert!(md.contains("abc123"), "change: {md}");
        assert!(md.contains("cafe0000"), "conflicted commit: {md}");
    }

    /// A deterministic host so `to_argv` is a pure function (mirrors spawn.rs).
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
    fn builder_produces_a_claude_command_with_the_merger_policy() {
        let cmd = worker_command(
            &root(),
            &rendered(),
            "resolve the conflict",
            DEFAULT_MAX_TURNS,
        );
        let spawn = match cmd {
            WorkerCommand::Claude(s) => s,
            _ => panic!("Merger builder must produce a Claude command"),
        };
        assert_eq!(spawn.role, WorkerRole::Merger);
        assert_eq!(spawn.allowlist, allowed_tools());
        assert_eq!(spawn.denylist, disallowed_tools());
        assert_eq!(spawn.system_prompt, system_prompt());
        assert_eq!(spawn.max_turns, 30);
        // The Merger sandbox binds the repo .jj/ + .git/ (committing role,
        // finding #1) — like the Implementer, unlike the Adversary.
        assert!(spawn.mounts.has_jj(), "Merger must get the repo .jj/");
        assert!(
            spawn.mounts.has_git(),
            "Merger must get the colocated .git/"
        );
    }

    #[test]
    fn to_argv_is_headless_default_never_dangerous() {
        let cmd = worker_command(&root(), &rendered(), "resolve", DEFAULT_MAX_TURNS);
        let spawn = match cmd {
            WorkerCommand::Claude(s) => s,
            _ => unreachable!(),
        };
        let argv = spawn.to_argv(&ws(), &test_host());
        let sep = argv.iter().position(|a| a == "--").expect("separator");
        let run = &argv[sep + 4];
        assert!(run.starts_with("claude "), "run string: {run}");
        assert!(run.contains("-p "), "headless -p: {run}");
        assert!(run.contains("--permission-mode default"));
        assert!(run.contains("--max-turns 30"));
        assert!(run.contains("--allowed-tools"));
        assert!(
            run.contains("--disallowed-tools"),
            "deny list rides through"
        );
        assert!(
            !run.contains("--dangerously-skip-permissions"),
            "REQ-4: never --dangerously-skip-permissions"
        );
        // The blocked verbs are not in the allowlist but ARE in the deny list.
        assert!(
            !allowed_tools().contains("jj rebase"),
            "blocked verb must not be allowlisted"
        );
        assert!(
            run.contains("jj resolve:*"),
            "allowlist rode through: {run}"
        );
        assert!(
            run.contains("jj rebase:*"),
            "deny list carries jj rebase: {run}"
        );
    }
}
