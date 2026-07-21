//! The **Adversary** role: allowlist, deny list, system prompt, turn cap, the
//! [`WorkerCommand`] builder, and the orchestrator-side pre-rendering of its
//! inputs (REQ-8, REQ-10 groundwork, A1).
//!
//! The Adversary reviews an Implementer's committed change with **fresh
//! context** and **no** ability to reach the repository VCS. Its sandbox binds
//! the workspace RW and `.crosslink/` RO, but — unlike the Implementer — gets
//! **no** repository `.jj/` and **no** `.git/` ([`MountMatrix::for_role`]). So
//! the Adversary never runs `jj diff`/`jj log`: the orchestrator renders those
//! into `_orchestrator/{diff.patch, log.txt, prior_findings.json, task.md}`
//! *before* the spawn ([`render_inputs`]), and the Adversary reads the files.
//!
//! The Adversary's job is to try to **refute** the change — correctness bugs,
//! missed requirements, security issues, weak tests — and write each finding as
//! one JSON line to `_orchestrator/findings.jsonl` (the [`crate::artifacts`]
//! `Findings` parser consumes it post-phase). A clean round (zero findings, an
//! *empty* `findings.jsonl`) is valid and important: it is the convergence
//! signal the iteration-2 loop (#22/#23) watches for. It never edits the
//! implementation, never commits, and never pushes — it has no VCS to commit to.
//!
//! Like the Implementer role, the allowlist + deny list are **guardrails, not a
//! cage** — see the threat-model block in [`crate::roles`]. The Adversary is a
//! *reviewer*, so its surface is deliberately narrower than the Implementer's:
//! no jj, no git, no `Edit` (it must not mutate the implementation), only
//! `Read`/`Write` plus `cargo build`/`cargo test` to *verify* a claim by
//! running a throwaway test.

use std::path::{Path, PathBuf};

use serde::Serialize;
use vetinari_error::AdversaryError;

use crate::artifacts::{Finding, ARTIFACT_DIR};
use crate::spawn::WorkerCommand;
use crate::state::WorkerRole;
use crate::workspace::WorkspaceManager;

/// The Adversary's default `--max-turns` cap (REQ-13 `max_turns_adversary`).
/// A worker hitting its turn cap is treated like any other crash (no DONE
/// sentinel → the pump re-spawns). Config-overridable via
/// `[worker] max_turns_adversary` once the pump wires the convergence loop
/// (#22/#23).
pub const DEFAULT_MAX_TURNS: u32 = 40;

/// The Adversary's default turn cap, [`DEFAULT_MAX_TURNS`]. A function so a call
/// site reads symmetrically with the other role knobs ([`allowed_tools`] etc.).
pub fn max_turns() -> u32 {
    DEFAULT_MAX_TURNS
}

/// The pre-rendered `diff.patch` input filename, relative to [`ARTIFACT_DIR`].
pub const DIFF_FILE: &str = "diff.patch";

/// The pre-rendered `log.txt` input filename, relative to [`ARTIFACT_DIR`].
pub const LOG_FILE: &str = "log.txt";

/// The pre-rendered `prior_findings.json` input filename, relative to
/// [`ARTIFACT_DIR`]. Always a valid JSON array (empty `[]` when there are no
/// prior rounds).
pub const PRIOR_FINDINGS_FILE: &str = "prior_findings.json";

/// The task input filename, relative to [`ARTIFACT_DIR`] (mirrors the
/// Implementer's `task.md`).
pub const TASK_FILE: &str = "task.md";

/// The Adversary's `--allowed-tools` tokens, as a **structured list** joined
/// once by [`allowed_tools`] — never a hand-typed blob, so the set is auditable
/// token-by-token.
///
/// A **guardrail, not a cage** (see [`crate::roles`]). It contains, and can only
/// ever contain, what is listed:
///
/// - [`Read`] / [`Write`] — read the pre-rendered inputs and the implementation
///   under review; write `_orchestrator/findings.jsonl`, `_orchestrator/result.md`,
///   and the DONE sentinel. `Write` creates files + parent dirs, so it also
///   covers a throwaway test file.
/// - `Bash(cargo build:*)` / `Bash(cargo test:*)` — the Adversary VERIFIES a
///   claim by writing a throwaway test and running it, rather than asserting a
///   bug it never reproduced.
/// - `Bash(sha256sum:*)` — the DONE manifest's per-artifact hash (REQ-3b).
///
/// It deliberately omits, and there is simply no token for:
///
/// - **`Edit`** — the Adversary must NOT mutate the implementation it reviews.
///   `Write` is present only for *new* files (findings, result, a throwaway
///   test); editing the change under review is off the table.
/// - **All `jj` verbs and `git`** — the Adversary has no repository `.jj/` /
///   `.git/` mount at all ([`MountMatrix::for_role`]) and never commits, pushes,
///   or inspects VCS; it reads the pre-rendered [`DIFF_FILE`] / [`LOG_FILE`]
///   instead (REQ-8). The known-dangerous of these are *also* named in
///   [`DISALLOWED_TOOLS`] for a clean refusal.
/// - A blanket `Bash(*)`, and gratuitous `Bash(mkdir:*)` / `Bash(cat:*)`
///   (`Write`/`Read` cover those).
///
/// [`Read`]: https://docs.anthropic.com/en/docs/claude-code
/// [`Write`]: https://docs.anthropic.com/en/docs/claude-code
/// [`MountMatrix::for_role`]: crate::spawn::MountMatrix::for_role
pub const ALLOWED_TOOLS: &[&str] = &[
    // Read the pre-rendered inputs + the change under review; write findings,
    // result, and a throwaway test. NO `Edit` — the Adversary never mutates the
    // implementation.
    "Read",
    "Write",
    // Verify a claim by running a throwaway test, rather than asserting an
    // unreproduced bug.
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

/// The Adversary's `--disallowed-tools` tokens: a clean-refusal deny list for
/// the VCS verbs it must never reach, joined once by [`disallowed_tools`].
///
/// Because `--permission-mode default` *asks* (rather than denies) for an
/// unlisted tool — and a headless worker has no one to answer, so the call
/// wedges until the pump's timeout (see [`crate::roles`]) — the verbs whose use
/// is most damaging get an explicit `--disallowed-tools` entry so `claude`
/// refuses them outright. The Adversary uses **no** jj at all, so the whole `jj`
/// surface is denied with a single blanket prefix rule (unlike the Implementer,
/// which must allow the commit verbs and so enumerates the blocked ones):
///
/// - `Bash(git:*)` — never any `git`.
/// - `Bash(jj:*)` — never *any* `jj` verb (commit, push/fetch, diff, log, …):
///   the Adversary reads the pre-rendered [`DIFF_FILE`] / [`LOG_FILE`] instead.
pub const DISALLOWED_TOOLS: &[&str] = &[
    // Never `git`.
    "Bash(git:*)",
    // Never ANY `jj` verb — no repo VCS mount, no commit, no push/fetch, and it
    // reads the pre-rendered diff/log rather than running `jj diff`/`jj log`.
    "Bash(jj:*)",
];

/// The `--disallowed-tools` value: [`DISALLOWED_TOOLS`] joined by `,`. Built from
/// the structured list once, so the wire value and the auditable token list can
/// never drift.
pub fn disallowed_tools() -> String {
    DISALLOWED_TOOLS.join(",")
}

/// The Adversary role system prompt, passed via `--append-system-prompt`.
///
/// Encodes the Adversary contract: review the Implementer's change with fresh
/// eyes, reading the pre-rendered inputs; try to REFUTE it; write each finding
/// as one JSON line to `_orchestrator/findings.jsonl` (an EMPTY file is a valid,
/// important clean round); do not edit the implementation, do not commit, do not
/// push; write the `_orchestrator/DONE` sentinel LAST (REQ-3b). The spawn layer
/// appends its own fixed "read your task file" instruction after this (REQ-8).
pub fn system_prompt() -> String {
    SYSTEM_PROMPT.to_owned()
}

/// The literal Adversary system prompt (see [`system_prompt`]).
const SYSTEM_PROMPT: &str = "\
You are the Adversary, an autonomous reviewer in the vetinari VDD orchestrator. \
You run with a fresh context each round and review an Implementer's committed \
change with fresh eyes. You have NO access to version control: you read \
pre-rendered inputs instead of running `jj`/`git`.

Read all of your pre-rendered inputs first, at the root of your working \
directory:

- `_orchestrator/diff.patch` — the Implementer's change, as a git-format diff. \
  This is the change you are reviewing; you never run `jj diff`.
- `_orchestrator/log.txt` — the commit log for the issue's change chain.
- `_orchestrator/prior_findings.json` — a JSON array of findings from prior \
  Adversary rounds (empty `[]` if this is the first round). Do not repeat a \
  prior finding the change already addressed.
- `_orchestrator/task.md` — the issue's task, so you know what the change was \
  supposed to accomplish.

Your job is to REFUTE the change: hunt for correctness bugs, missed \
requirements from the task, security issues, and weak or missing tests. You may \
write a THROWAWAY test and run `cargo build` / `cargo test` to VERIFY a claim \
before you make it — prefer a reproduced bug to a speculative one. Do NOT edit \
the implementation under review, do NOT commit, and do NOT push — you are a \
reviewer, not an author.

Record your review under `_orchestrator/`, in this order and with DONE strictly \
LAST:

1. Write `_orchestrator/findings.jsonl`: one JSON object per line, each \
   {\"severity\":\"high\"|\"med\"|\"low\",\"location\":\"path:line\",\"claim\":\"…\",\"evidence_files\":[\"…\"]}. \
   ALWAYS write this file, even when you found NOTHING: in that case write an \
   EMPTY `findings.jsonl` (zero bytes) AND still list it in your DONE \
   `artifacts` below. A clean round with no findings is valid and important — \
   it is how convergence is detected — but ONLY when the empty file is actually \
   present and DONE-attested; a missing `findings.jsonl` is read as a crashed \
   review, not a clean round. Never invent a finding to avoid an empty file.
2. Write `_orchestrator/result.md` summarizing what you reviewed and concluded.
3. Write `_orchestrator/DONE` as your VERY LAST filesystem operation. Its \
   content is JSON: {\"exit_status\":\"success\",\"artifacts\":[{\"path\":\"_orchestrator/findings.jsonl\",\"sha256\":\"<sha256 of findings.jsonl>\"},{\"path\":\"_orchestrator/result.md\",\"sha256\":\"<sha256 of result.md>\"}]}. \
   Use `sha256sum` to compute each hash. If you could not complete the review, \
   set \"exit_status\":\"error\" instead.

Constraints: stay within your workspace directory. Never read or write the \
orchestrator-private `.orchestrator/` directory (note the leading dot — it is \
distinct from the `_orchestrator/` inputs/outputs above). Never edit the \
implementation, commit, push, or attempt any version-control command.";

/// Build the Adversary [`WorkerCommand::Claude`] for `task`, run in the
/// pre-rendered `rendered` workspace under the repository `root`, capped at
/// `max_turns`.
///
/// A thin wrapper over [`WorkerCommand::claude`] that pins the role to
/// [`WorkerRole::Adversary`] and supplies this module's [`allowed_tools`],
/// [`disallowed_tools`], and [`system_prompt`] — the caller only chooses the
/// task and the (config-derived) turn cap, so the security-critical allowlist,
/// deny list, and prompt cannot be forgotten or overridden at a call site. The
/// derived [`MountMatrix`](crate::spawn::MountMatrix) gives the Adversary **no**
/// repository `.jj/` / `.git/`.
///
/// The workspace is taken from a [`RenderedAdversaryInputs`] token — the typed
/// proof that [`render_inputs`] populated `_orchestrator/{diff.patch, log.txt,
/// …}` first (mirroring the [`PreparedWorkspace`](crate::workspace::PreparedWorkspace)
/// pattern). You **cannot** spawn an Adversary without having rendered its
/// inputs, so a forgotten pre-render (⇒ an absent `diff.patch` ⇒ an infinite
/// crash/re-spawn loop) is unrepresentable at the type level.
pub fn worker_command(
    root: &Path,
    rendered: &RenderedAdversaryInputs,
    task: impl Into<String>,
    max_turns: u32,
) -> WorkerCommand {
    WorkerCommand::claude(
        WorkerRole::Adversary,
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
// Input pre-rendering (REQ-8, A1)
// ============================================================================

/// The parameters for one Adversary input pre-render ([`render_inputs`]).
///
/// Grouped in a struct rather than passed as a long argument list so the call
/// site reads by field and a new input is a named addition, not a positional
/// footgun.
#[derive(Debug, Clone, Copy)]
pub struct RenderParams<'a> {
    /// Revset naming the base to diff the change *from* (the change's parent —
    /// e.g. `X-` — or the trunk the chain sits on). `diff.patch` is
    /// `diff(diff_from -> diff_to)`.
    pub diff_from: &'a str,
    /// Revset naming the Implementer's committed change to diff *to*.
    pub diff_to: &'a str,
    /// Revset naming the issue's change chain to render into `log.txt` (e.g.
    /// `main..X` or the change itself).
    pub log_revset: &'a str,
    /// Prior rounds' findings, serialized into `prior_findings.json` (empty
    /// slice → `[]`).
    pub prior_findings: &'a [Finding],
    /// The task text written to `_orchestrator/task.md` (typically
    /// [`crate::roles::implementer::task_from_issue`]'s output).
    pub task: &'a str,
}

/// The `prior_findings.json` wire shape for one finding — the *same* schema as a
/// `findings.jsonl` line, so the Adversary reads prior findings in exactly the
/// format it writes new ones. Private: it exists only to serialize a
/// [`Finding`] (whose `location` is a structured `Location`) back to the flat
/// `"path:line"` string form.
#[derive(Serialize)]
struct PriorFinding<'a> {
    severity: &'a str,
    location: String,
    claim: &'a str,
    evidence_files: &'a [String],
}

impl<'a> From<&'a Finding> for PriorFinding<'a> {
    fn from(f: &'a Finding) -> Self {
        PriorFinding {
            severity: f.severity.as_str(),
            location: f.location.to_string(),
            claim: &f.claim,
            evidence_files: &f.evidence_files,
        }
    }
}

/// Pre-render the Adversary's inputs into `<workspace>/_orchestrator/` (REQ-8,
/// A1), BEFORE the Adversary spawn.
///
/// Writes four files the Adversary reads instead of touching `.jj/`:
///
/// - **`diff.patch`** — `diff(params.diff_from -> params.diff_to)`, the
///   Implementer's change as a git-format patch, rendered through the `.jj/`
///   gate ([`WorkspaceManager::diff`]).
/// - **`log.txt`** — the commit log for `params.log_revset`
///   ([`WorkspaceManager::log`]), formatted deterministically ([`format_log`]).
/// - **`prior_findings.json`** — `params.prior_findings` as a JSON array in the
///   `findings.jsonl` schema (an empty `[]` when there are no prior rounds).
/// - **`task.md`** — `params.task` verbatim.
///
/// The `.jj/` reads and the file writes are the two failure classes, each a
/// typed [`AdversaryError`] (never a panic): a `jj_api` diff/log failure is
/// [`AdversaryError::Render`]; a filesystem write failure is
/// [`AdversaryError::Io`]. Creates the `_orchestrator/` parent if absent.
///
/// No shell-out (AC-24): the diff/log come from `jj_api` through the manager's
/// gate, JSON from `serde_json`, and every write from [`std::fs`].
///
/// On success returns a [`RenderedAdversaryInputs`] token: the typed proof the
/// inputs exist, which [`worker_command`] requires to spawn the Adversary — so
/// the spawn cannot outrun the pre-render.
pub fn render_inputs(
    manager: &WorkspaceManager,
    workspace: &Path,
    params: &RenderParams<'_>,
) -> Result<RenderedAdversaryInputs, AdversaryError> {
    let dir = workspace.join(ARTIFACT_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| AdversaryError::io(&dir, e))?;

    // diff.patch — the change under review (rendered on the Adversary's behalf).
    let patch = manager
        .diff(params.diff_from, params.diff_to)
        .map_err(|source| AdversaryError::Render {
            input: DIFF_FILE,
            source: Box::new(source),
        })?;
    write_input(&dir, DIFF_FILE, &patch)?;

    // log.txt — the issue's change chain, formatted deterministically.
    let commits = manager
        .log(params.log_revset)
        .map_err(|source| AdversaryError::Render {
            input: LOG_FILE,
            source: Box::new(source),
        })?;
    write_input(&dir, LOG_FILE, &format_log(&commits))?;

    // prior_findings.json — a JSON array in the findings.jsonl schema ([] if
    // none). A serialization failure is PROPAGATED, never silently emptied to
    // `[]`: an empty prior-findings input is the worst-direction default for a
    // convergence round (the Adversary would re-report already-addressed
    // findings), so the error must surface rather than vanish.
    let prior: Vec<PriorFinding<'_>> = params
        .prior_findings
        .iter()
        .map(PriorFinding::from)
        .collect();
    let prior_json = serde_json::to_string(&prior).map_err(|source| AdversaryError::Serialize {
        input: PRIOR_FINDINGS_FILE,
        source: Box::new(source),
    })?;
    write_input(&dir, PRIOR_FINDINGS_FILE, &prior_json)?;

    // task.md — the issue task, verbatim (mirrors the Implementer's task.md).
    write_input(&dir, TASK_FILE, params.task)?;

    Ok(RenderedAdversaryInputs {
        workspace: workspace.to_path_buf(),
    })
}

/// Typed proof that [`render_inputs`] populated an Adversary workspace's
/// `_orchestrator/` inputs (`diff.patch`, `log.txt`, `prior_findings.json`,
/// `task.md`) — the render-side mirror of
/// [`PreparedWorkspace`](crate::workspace::PreparedWorkspace).
///
/// [`worker_command`] takes one of these instead of a bare workspace path, so
/// an Adversary cannot be spawned into a workspace whose inputs were never
/// rendered. Its only constructor is [`render_inputs`]; there is no `pub` field
/// and no other way to mint one, so "an un-rendered Adversary spawn" is
/// unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedAdversaryInputs {
    /// Absolute path of the workspace whose inputs were rendered.
    workspace: PathBuf,
}

impl RenderedAdversaryInputs {
    /// The workspace whose `_orchestrator/` inputs were pre-rendered.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

/// Write one pre-rendered input file `<dir>/<name>`, mapping any I/O failure to
/// [`AdversaryError::Io`] with the offending path.
fn write_input(dir: &Path, name: &str, content: &str) -> Result<(), AdversaryError> {
    let path = dir.join(name);
    std::fs::write(&path, content).map_err(|e| AdversaryError::io(&path, e))
}

/// Format a commit list into the deterministic `log.txt` text the Adversary
/// reads. One stanza per commit, in the order `jj_api` returned them (newest
/// first for an ancestor set). Pure and total — no I/O, no `jj` subprocess.
///
/// An **empty** `commits` slice yields an empty string: a valid, if vacuous,
/// `log.txt`. That only happens if the issue's `log_revset` resolved to no
/// commits (an empty chain) — the Adversary still gets a (zero-byte) `log.txt`
/// to read, never a missing input.
fn format_log(commits: &[vetinari_jj_api::CommitInfo]) -> String {
    let mut out = String::new();
    for c in commits {
        out.push_str("commit ");
        out.push_str(&c.commit_id);
        out.push_str(" (change ");
        out.push_str(&c.change_id);
        out.push(')');
        if c.has_conflict {
            out.push_str(" [conflict]");
        }
        out.push('\n');
        out.push_str("Author: ");
        out.push_str(&c.author_name);
        out.push_str(" <");
        out.push_str(&c.author_email);
        out.push_str(">\n");
        // Blank line, then the description indented, mirroring `git log`.
        out.push('\n');
        if c.description.trim().is_empty() {
            out.push_str("    (no description set)\n");
        } else {
            for line in c.description.lines() {
                out.push_str("    ");
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push('\n');
    }
    out
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
        PathBuf::from("/repo/.workspace/adversary-review-42-r1-a1b2c3d4")
    }

    /// A render token for [`ws`] — stands in for a real [`render_inputs`] call
    /// so the pure `worker_command`/`to_argv` builder tests need no filesystem.
    /// (The on-disk render is covered by the `tests/adversary.rs` integration
    /// tests.) Legal here because these unit tests are a child module of the one
    /// that defines the token's private field.
    fn rendered() -> RenderedAdversaryInputs {
        RenderedAdversaryInputs { workspace: ws() }
    }

    /// Tokens that must NEVER appear anywhere in the Adversary allowlist: it has
    /// no repository `.jj/`/`.git/` mount and never commits, pushes, or edits.
    const FORBIDDEN: &[&str] = &[
        "jj", "git", "commit", "push", "fetch", "abandon", "rebase", "squash", "split", "Edit",
        "Bash(*)",
    ];

    #[test]
    fn allowlist_permits_read_write_and_cargo_verify_tools() {
        let a = allowed_tools();
        for tool in ["Read", "Write", "cargo build", "cargo test", "sha256sum"] {
            assert!(a.contains(tool), "allowlist must permit `{tool}`: {a}");
        }
    }

    #[test]
    fn allowlist_excludes_every_vcs_and_edit_token() {
        let a = allowed_tools();
        for bad in FORBIDDEN {
            assert!(
                !a.contains(bad),
                "Adversary allowlist must NOT contain `{bad}`: {a}"
            );
        }
    }

    #[test]
    fn allowlist_is_the_structured_list_joined_once() {
        assert_eq!(allowed_tools(), ALLOWED_TOOLS.join(","));
        assert!(!a_contains_gratuitous_helpers());
    }

    fn a_contains_gratuitous_helpers() -> bool {
        let a = allowed_tools();
        a.contains("mkdir") || a.contains("cat:")
    }

    #[test]
    fn deny_list_denies_git_and_all_jj() {
        let d = disallowed_tools();
        // git and a blanket jj deny — cleanly refused, both directions.
        assert!(d.contains("Bash(git:*)"), "deny list must name git: {d}");
        assert!(
            d.contains("Bash(jj:*)"),
            "deny list must blanket-deny all jj: {d}"
        );
        assert_eq!(disallowed_tools(), DISALLOWED_TOOLS.join(","));
        // The deny list carries the VCS tokens the allowlist must lack.
        for bad in ["jj", "git"] {
            assert!(d.contains(bad), "deny list must carry `{bad}`: {d}");
            assert!(
                !allowed_tools().contains(bad),
                "allowlist must not carry `{bad}`"
            );
        }
    }

    #[test]
    fn max_turns_default_is_40() {
        assert_eq!(DEFAULT_MAX_TURNS, 40);
        assert_eq!(max_turns(), 40);
    }

    #[test]
    fn system_prompt_states_the_review_contract() {
        let p = system_prompt();
        // References every pre-rendered input.
        assert!(p.contains("_orchestrator/diff.patch"), "reads diff.patch");
        assert!(p.contains("_orchestrator/log.txt"), "reads log.txt");
        assert!(
            p.contains("_orchestrator/prior_findings.json"),
            "reads prior_findings.json"
        );
        assert!(p.contains("_orchestrator/task.md"), "reads task.md");
        // Writes findings.jsonl, empty-is-valid rule.
        assert!(
            p.contains("_orchestrator/findings.jsonl"),
            "writes findings.jsonl"
        );
        assert!(
            p.to_lowercase().contains("empty"),
            "states the empty-findings-is-valid rule"
        );
        // No-commit / no-edit-impl.
        assert!(p.to_lowercase().contains("commit"), "forbids committing");
        assert!(
            p.to_lowercase().contains("edit the implementation"),
            "forbids editing the implementation"
        );
        // DONE last.
        assert!(p.contains("_orchestrator/DONE"), "writes DONE");
        assert!(p.to_lowercase().contains("last"), "DONE written LAST");
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
    fn builder_produces_a_claude_command_with_the_adversary_policy() {
        let cmd = worker_command(&root(), &rendered(), "review the change", DEFAULT_MAX_TURNS);
        let spawn = match cmd {
            WorkerCommand::Claude(s) => s,
            _ => panic!("Adversary builder must produce a Claude command"),
        };
        assert_eq!(spawn.role, WorkerRole::Adversary);
        assert_eq!(spawn.allowlist, allowed_tools());
        assert_eq!(spawn.denylist, disallowed_tools());
        assert_eq!(spawn.system_prompt, system_prompt());
        assert_eq!(spawn.max_turns, 40);
        // The Adversary gets NO repository `.jj/` / `.git/` (REQ-5, REQ-5a).
        assert!(!spawn.mounts.has_jj(), "Adversary must have no repo .jj/");
        assert!(!spawn.mounts.has_git(), "Adversary must have no .git/");
    }

    #[test]
    fn to_argv_is_headless_default_never_dangerous() {
        let cmd = worker_command(&root(), &rendered(), "review", DEFAULT_MAX_TURNS);
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
        assert!(run.contains("--max-turns 40"));
        assert!(run.contains("--allowed-tools"));
        assert!(
            run.contains("--disallowed-tools"),
            "deny list rides through"
        );
        // REQ-4: never the dangerous skip.
        assert!(
            !run.contains("--dangerously-skip-permissions"),
            "REQ-4: never --dangerously-skip-permissions"
        );
        // Prove the assembled argv — not just the source `allowed_tools()`
        // string — carries no jj/git in its ALLOWLIST, while the blanket jj/git
        // deny DID ride through. Assert on the actual `--allowed-tools` /
        // `--disallowed-tools` values inside the inspectable `claude_argv`
        // (mirrors the Implementer tests), so a builder that leaked a VCS verb
        // into the wire allowlist would fail here.
        let inner = spawn.claude_argv();
        let value_after = |flag: &str| -> String {
            let i = inner
                .iter()
                .position(|a| a == flag)
                .unwrap_or_else(|| panic!("{flag} present in argv: {inner:?}"));
            inner[i + 1].clone()
        };
        let allow = value_after("--allowed-tools");
        let deny = value_after("--disallowed-tools");
        assert!(
            !allow.contains("jj"),
            "assembled allowlist has no jj: {allow}"
        );
        assert!(
            !allow.contains("git"),
            "assembled allowlist has no git: {allow}"
        );
        assert!(deny.contains("jj:*"), "assembled deny blankets jj: {deny}");
        assert!(deny.contains("git:*"), "assembled deny carries git: {deny}");
    }

    #[test]
    fn prior_finding_serializes_in_findings_schema() {
        // A prior finding round-trips through the `findings.jsonl` wire shape:
        // `location` collapses back to the flat `"path:line"` string.
        use crate::artifacts::Findings;
        let jsonl = r#"{"severity":"high","location":"src/lib.rs:12","claim":"unsafe","evidence_files":["src/lib.rs"]}"#;
        let findings = Findings::parse(Path::new("f.jsonl"), jsonl).expect("parse");
        let prior: Vec<PriorFinding<'_>> =
            findings.findings().iter().map(PriorFinding::from).collect();
        let json = serde_json::to_string(&prior).expect("serialize");
        assert!(json.starts_with('['), "an array: {json}");
        assert!(
            json.contains(r#""location":"src/lib.rs:12""#),
            "flat location: {json}"
        );
        assert!(json.contains(r#""severity":"high""#), "{json}");
        // Each array element re-parses as a `findings.jsonl` line (schema
        // round-trip): rebuild a jsonl body from the array (one object per line)
        // and feed it back through the S3 parser.
        let array: Vec<serde_json::Value> = serde_json::from_str(&json).expect("array");
        let jsonl_body = array
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let reparsed = Findings::parse(Path::new("f.jsonl"), &jsonl_body).expect("reparse");
        assert_eq!(reparsed.findings().len(), 1);
        assert_eq!(reparsed.findings()[0].location.to_string(), "src/lib.rs:12");
    }

    #[test]
    fn empty_prior_findings_serialize_to_empty_array() {
        let prior: Vec<PriorFinding<'_>> = Vec::new();
        assert_eq!(serde_json::to_string(&prior).expect("serialize"), "[]");
    }

    #[test]
    fn format_log_renders_deterministic_stanzas() {
        let commits = vec![vetinari_jj_api::CommitInfo {
            commit_id: "abc123".to_owned(),
            change_id: "zzz".to_owned(),
            description: "Add say_hi\n".to_owned(),
            author_name: "Agent".to_owned(),
            author_email: "a@b.c".to_owned(),
            parent_ids: vec!["p1".to_owned()],
            has_conflict: false,
        }];
        let text = format_log(&commits);
        assert!(text.contains("commit abc123"), "{text}");
        assert!(text.contains("(change zzz)"), "{text}");
        assert!(text.contains("Author: Agent <a@b.c>"), "{text}");
        assert!(
            text.contains("    Add say_hi"),
            "indented description: {text}"
        );
        // Deterministic.
        assert_eq!(text, format_log(&commits));
    }
}
