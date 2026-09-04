//! The **Implementer** role: allowlist, deny list, system prompt, turn cap, and
//! the [`WorkerCommand`] builder (REQ-4, REQ-5, REQ-13, S7).
//!
//! The Implementer writes code against an issue in its jj workspace and commits
//! it via `jj`. Its sandbox binds the repository `.jj/` and `.git/` **RW** (the
//! colocated backend is unavoidable — see [`crate::spawn`]).
//!
//! The [`ALLOWED_TOOLS`] list + the [`DISALLOWED_TOOLS`] deny list shape what the
//! worker is *nudged* toward — the intended `jj` commit path is the easy one and
//! the obviously-dangerous verbs are refused. But be honest about what they are
//! **not**: they are **not** a hard VCS-isolation boundary. See the threat-model
//! block in [`crate::roles`] for the load-bearing truth — `Bash(cargo …)` runs
//! arbitrary compiled code and `Write`/`Edit` can touch the RW `.jj/`/`.git/`,
//! so a determined worker is not contained by any jj-verb allowlist. What
//! actually keeps a bad change off `main` is orchestrator-side validation before
//! landing (the QA gate, the fast-forward-guarded landing, adversary review).

use std::path::Path;

use crate::artifacts::{Finding, ARTIFACT_DIR};
use crate::spawn::WorkerCommand;
use crate::state::WorkerRole;

/// The prior-findings input filename the pump delivers into the Implementer's
/// workspace (REQ-8), relative to [`ARTIFACT_DIR`]. The Implementer's analogue of
/// the Adversary's `prior_findings.json`, but in the `findings.jsonl` line schema
/// (one finding per line; an empty file when there are none) that a generalized
/// worker reads directly.
pub const PRIOR_FINDINGS_FILE: &str = "prior_findings.jsonl";

/// Render the accumulated Adversary `prior_findings` into the prepared
/// Implementer workspace's `_orchestrator/prior_findings.jsonl` (REQ-8), BEFORE
/// the spawn — so a re-implement round's worker reads the findings it must
/// address as a workspace input, exactly as the Adversary reads its
/// pre-rendered `prior_findings.json`.
///
/// Delivered on EVERY round (a zero-byte file on the first, no-findings round),
/// so the worker can always read a well-formed input rather than probe for a
/// possibly-absent file. `_orchestrator/` is gitignored in the target repo, so
/// this input never snapshots into the Implementer's change.
///
/// This is the delivery channel a **Direct**/generalized worker uses (the live
/// `claude` Implementer additionally receives the same findings appended to its
/// `task.md` — see the pump's `append_prior_findings`). No shell-out (AC-24):
/// [`serde_json`](serde_json) via [`Finding::to_jsonl_line`] + [`std::fs`].
pub fn render_prior_findings(workspace: &Path, prior_findings: &[Finding]) -> std::io::Result<()> {
    let dir = workspace.join(ARTIFACT_DIR);
    std::fs::create_dir_all(&dir)?;
    let mut body = String::new();
    for finding in prior_findings {
        body.push_str(&finding.to_jsonl_line().map_err(std::io::Error::other)?);
        body.push('\n');
    }
    std::fs::write(dir.join(PRIOR_FINDINGS_FILE), body)
}

/// The Implementer's default `--max-turns` cap (REQ-13 `max_turns_implementer`).
/// A worker hitting its turn cap is treated like any other crash (no DONE
/// sentinel → the pump re-spawns). Config-overridable via
/// `[worker] max_turns_implementer` — see [`crate::config`].
pub const DEFAULT_MAX_TURNS: u32 = 80;

/// The Implementer's `--allowed-tools` tokens, as a **structured list** joined
/// once by [`allowed_tools`] — never a hand-typed blob, so the set is auditable
/// token-by-token and a new entry is a deliberate line here.
///
/// This is a **guardrail, not a cage** (see the module docs and
/// [`crate::roles`]): it scopes the worker to the intended `jj` commit path and
/// keeps the obviously-dangerous verbs off the easy path, but because the tree
/// and the RW `.jj/`/`.git/` are reachable through `Bash(cargo …)` and
/// `Write`/`Edit`, it does not *contain* a determined worker. It contains, and
/// can only ever contain, what is listed:
///
/// - The REQ-5 **ALLOWED** jj subcommands, each as a `Bash(jj <verb>:*)` prefix
///   rule: `describe`, `commit`, `new`, `diff`, `show`, `log`, `status`,
///   `files`. These are "edit the working copy, commit it, and inspect it" —
///   nothing that rewrites history or touches the global operation log.
/// - The file-edit tools: [`Read`], [`Edit`], [`Write`]. `Write` creates files
///   (and their parent directories), so it covers assembling `_orchestrator/`.
/// - The build/test tools the Implementer runs to self-verify before writing
///   its DONE sentinel: `cargo build`/`test`/`fmt`/`clippy`.
/// - `sha256sum` — the DONE manifest's per-artifact hash (REQ-3b).
///
/// It deliberately omits `Bash(mkdir:*)` and `Bash(cat:*)`: `Write` already
/// creates files and their parents, and `Read` covers inspection, so neither is
/// needed and every extra `Bash(<cmd>:*)` is one more prompt-free command.
///
/// It also does not list (there is simply no token for them):
///
/// - `git` in any form, and `jj git push`/`jj git fetch` — a worker is not
///   *meant* to reach a remote; the orchestrator owns landing (REQ-5, REQ-17).
/// - The REQ-5 **BLOCKED** jj verbs: `abandon`, `op undo`/`op restore`,
///   `workspace forget`/`add`/`list`, `edit`, `rebase`, `squash`, `split` —
///   history rewriting and operation-log surgery.
/// - A blanket `Bash(*)`.
///
/// The known-dangerous of these are *also* named explicitly in
/// [`DISALLOWED_TOOLS`], so they are cleanly refused rather than left to the
/// (headless-hanging) ASK behavior of `--permission-mode default`.
///
/// [`Read`]: https://docs.anthropic.com/en/docs/claude-code
/// [`Edit`]: https://docs.anthropic.com/en/docs/claude-code
/// [`Write`]: https://docs.anthropic.com/en/docs/claude-code
pub const ALLOWED_TOOLS: &[&str] = &[
    // REQ-5 ALLOWED jj subcommands — the intended VCS surface. `:*` is a Claude
    // Code prefix rule: `Bash(jj commit:*)` permits `jj commit` with any args
    // but not, e.g., `jj commit-and-push` (a different verb) or `jj abandon`.
    "Bash(jj describe:*)",
    "Bash(jj commit:*)",
    "Bash(jj new:*)",
    "Bash(jj diff:*)",
    "Bash(jj show:*)",
    "Bash(jj log:*)",
    "Bash(jj status:*)",
    "Bash(jj files:*)",
    // File-edit tools. `Write` creates files + parent dirs, so it also covers
    // assembling the `_orchestrator/` outputs — no `mkdir`/`cat` needed.
    "Read",
    "Edit",
    "Write",
    // Build/test tools: the Implementer self-verifies before DONE.
    "Bash(cargo build:*)",
    "Bash(cargo test:*)",
    "Bash(cargo fmt:*)",
    "Bash(cargo clippy:*)",
    // Artifact-contract helper (REQ-3b): the DONE manifest's per-artifact hash.
    "Bash(sha256sum:*)",
];

/// The `--allowed-tools` value: [`ALLOWED_TOOLS`] joined by `,` (Claude Code's
/// allowlist separator). Built from the structured list once, so the wire value
/// and the auditable token list can never drift.
pub fn allowed_tools() -> String {
    ALLOWED_TOOLS.join(",")
}

/// The Implementer's `--disallowed-tools` tokens: a belt-and-suspenders deny
/// list of the known-dangerous VCS verbs, joined once by [`disallowed_tools`].
///
/// # Why an explicit deny list on top of the allowlist
///
/// `--permission-mode default` does **not** cleanly deny an unlisted tool — it
/// *asks*. A headless worker (no stdin, [`crate::spawn`]) has no one to answer
/// that prompt, so an unlisted tool call **wedges** the worker until the pump's
/// `worker_timeout` treats the stall as a crash. That timeout is the backstop,
/// but it is slow and indirect. For the verbs whose accidental use is most
/// damaging — reaching a remote, or rewriting the shared history/op-log — an
/// explicit `--disallowed-tools` entry makes `claude` refuse the call outright,
/// no prompt, no hang.
///
/// This is defense-in-depth against *accidental* damage, **not** a cage: it does
/// not (and cannot) stop a worker that reaches the RW `.jj/`/`.git/` via
/// `Bash(cargo …)` or `Write`. The real boundary is orchestrator-side validation
/// before landing — see [`crate::roles`].
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
];

/// The `--disallowed-tools` value: [`DISALLOWED_TOOLS`] joined by `,`. Built from
/// the structured list once, so the wire value and the auditable token list can
/// never drift.
pub fn disallowed_tools() -> String {
    DISALLOWED_TOOLS.join(",")
}

/// The Implementer role system prompt, passed via `--append-system-prompt`.
///
/// Encodes the Implementer's contract: read the task (and any prior findings)
/// from `_orchestrator/task.md`, implement it in the workspace, commit via `jj
/// describe`/`jj commit`, then write `_orchestrator/result.md` and, **last**,
/// the `_orchestrator/DONE` sentinel (REQ-3b). It stays inside the workspace,
/// never touches the orchestrator-private `.orchestrator/` directory, and never
/// pushes — landing is the orchestrator's job (REQ-17). The spawn layer appends
/// its own fixed "read your task file" instruction after this (REQ-8).
pub fn system_prompt() -> String {
    SYSTEM_PROMPT.to_owned()
}

/// The literal Implementer system prompt (see [`system_prompt`]).
const SYSTEM_PROMPT: &str = "\
You are the Implementer, an autonomous coding worker in the vetinari VDD \
orchestrator. You run with a fresh context each round.

Your task for this round is written to `_orchestrator/task.md` at the root of \
your working directory. Read it first. If it references prior Adversary \
findings or a QA blocker, address every one of them.

Do the work directly in your workspace: edit files, then verify with the \
build/test tools available to you (`cargo build`, `cargo test`, `cargo fmt`, \
`cargo clippy`). Commit your change with `jj describe` (to set the commit \
message) and `jj commit`/`jj new` as needed — do NOT run any other version \
control command. You have no access to `git`, to pushing/fetching, or to \
history-rewriting jj verbs, and you never need them: the orchestrator lands \
your change for you.

When the implementation is complete and verified, produce your artifacts under \
`_orchestrator/`, in this order and with DONE strictly LAST:

1. Write `_orchestrator/result.md` describing what you changed and which task \
   items / prior findings it addressed.
2. OPTIONAL: if — while doing this task — you discovered follow-up work that is \
   OUT OF SCOPE for this issue (\"we also need to parse sub-record Y\", \"Z is \
   blocked on recovering enum W\"), you MAY write `_orchestrator/followups.jsonl`, \
   one JSON object per line: {\"title\":\"<one line>\",\"rationale\":\"<why>\",\"suggested_blockers\":[<issue numbers>],\"gate_sketch\":\"<how it'd be verified>\"}. \
   Only `title` and `rationale` are required. These are PROPOSALS a human \
   reviews and may later graph — they are NOT scheduled automatically, and you \
   must NOT try to create issues, set labels, or add blockers yourself (you have \
   read-only access to the tracker, by design). Omit the file entirely if you \
   found no follow-up work.
3. Write `_orchestrator/DONE` as your VERY LAST filesystem operation. Its \
   content is JSON: {\"exit_status\":\"success\",\"artifacts\":[{\"path\":\"_orchestrator/result.md\",\"sha256\":\"<sha256 of result.md>\"}]}. \
   List EVERY artifact you wrote under `_orchestrator/` (including \
   `followups.jsonl` if you wrote it) in the `artifacts` array with its \
   `sha256`. Use `sha256sum` to compute each hash. If you could not complete the \
   task, set \"exit_status\":\"error\" instead.

Constraints: stay within your workspace directory. Never read or write the \
orchestrator-private `.orchestrator/` directory (note the leading dot — it is \
distinct from the `_orchestrator/` outputs above). Never attempt to push, \
open a pull request, or move a bookmark.";

/// Assemble the per-round task file content from a crosslink issue's title and
/// optional description (REQ-8). This is what the pump writes to
/// `_orchestrator/task.md` for a Claude Implementer spawn.
///
/// **UNTRUSTED INPUT (prompt-injection surface).** The title/description come
/// from crosslink and become the worker's instructions verbatim — a hostile
/// issue body could try to talk the worker into ignoring its role prompt,
/// touching `.orchestrator/`, or attempting a denied VCS verb. We do **not**
/// try to sanitize the text (that is a losing game). The mitigation is the same
/// one that protects `main` generally: orchestrator-side validation before
/// landing (the QA gate, the fast-forward-guarded landing that can only advance
/// trunk, and adversary review), never trust in the worker. See the threat-model
/// block in [`crate::roles`].
pub fn task_from_issue(title: &str, description: Option<&str>) -> String {
    match description {
        Some(body) if !body.trim().is_empty() => format!("# {title}\n\n{body}"),
        _ => format!("# {title}"),
    }
}

/// Build the Implementer [`WorkerCommand::Claude`] for `task`, run in the
/// prepared `workspace` under the repository `root`, capped at `max_turns`.
///
/// A thin wrapper over [`WorkerCommand::claude`] that pins the role to
/// [`WorkerRole::Implementer`] and supplies this module's [`allowed_tools`],
/// [`disallowed_tools`], and [`system_prompt`] — the caller only chooses the
/// task and the (config-derived) turn cap, so the security-critical allowlist,
/// deny list, and prompt cannot be forgotten or overridden at a call site.
pub fn worker_command(
    root: &Path,
    workspace: &Path,
    task: impl Into<String>,
    max_turns: u32,
) -> WorkerCommand {
    WorkerCommand::claude(
        WorkerRole::Implementer,
        root,
        workspace,
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
    use crate::state::WorkerRole;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from("/repo")
    }

    fn ws() -> PathBuf {
        PathBuf::from("/repo/.workspace/implementing-42-r0-a1b2c3d4")
    }

    /// The REQ-5 ALLOWED jj subcommands — every one must be present.
    const ALLOWED_JJ: &[&str] = &[
        "jj describe",
        "jj commit",
        "jj new",
        "jj diff",
        "jj show",
        "jj log",
        "jj status",
        "jj files",
    ];

    /// The REQ-5 BLOCKED tokens (plus `git` and the blanket bash) — NONE may
    /// appear anywhere in the rendered allowlist.
    const FORBIDDEN: &[&str] = &[
        "git",
        "jj git push",
        "jj git fetch",
        "jj abandon",
        "jj op",
        "jj workspace",
        "jj rebase",
        "jj squash",
        "jj split",
        "jj edit",
        "Bash(*)",
    ];

    #[test]
    fn allowlist_contains_every_allowed_jj_subcommand() {
        let a = allowed_tools();
        for verb in ALLOWED_JJ {
            assert!(
                a.contains(verb),
                "allowlist must permit `{verb}` (REQ-5 ALLOWED): {a}"
            );
        }
        // The edit + build tools the Implementer needs.
        for tool in [
            "Read",
            "Edit",
            "Write",
            "cargo build",
            "cargo test",
            "cargo fmt",
            "cargo clippy",
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
                "allowlist must NOT contain `{bad}` (REQ-5 BLOCKED / VCS bypass): {a}"
            );
        }
    }

    #[test]
    fn allowlist_is_the_structured_list_joined_once() {
        // The wire value is exactly the structured tokens joined by `,` — no
        // stray blob, no duplication.
        assert_eq!(allowed_tools(), ALLOWED_TOOLS.join(","));
        // Every jj token is a `:*` prefix rule (a bare `Bash(jj)` would be a
        // wildcard over all jj verbs — that must not happen).
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
    fn max_turns_default_is_80() {
        assert_eq!(DEFAULT_MAX_TURNS, 80);
    }

    #[test]
    fn allowlist_omits_gratuitous_bash_helpers() {
        // `Write` covers file+dir creation and `Read` covers inspection, so
        // `mkdir`/`cat` are not needed — every extra `Bash(cmd:*)` is one more
        // prompt-free command, so keep the set minimal.
        let a = allowed_tools();
        assert!(!a.contains("mkdir"), "mkdir must not be allowlisted: {a}");
        assert!(!a.contains("cat:"), "cat must not be allowlisted: {a}");
    }

    #[test]
    fn deny_list_names_the_known_dangerous_verbs() {
        let d = disallowed_tools();
        for verb in [
            "Bash(git:*)",
            "Bash(jj git push:*)",
            "Bash(jj git fetch:*)",
            "Bash(jj abandon:*)",
            "Bash(jj op:*)",
            "Bash(jj rebase:*)",
            "Bash(jj squash:*)",
            "Bash(jj split:*)",
            "Bash(jj edit:*)",
            "Bash(jj workspace:*)",
        ] {
            assert!(d.contains(verb), "deny list must name `{verb}`: {d}");
        }
        // The deny list is the structured tokens joined once — no drift.
        assert_eq!(disallowed_tools(), DISALLOWED_TOOLS.join(","));
    }

    #[test]
    fn system_prompt_states_the_contract() {
        let p = system_prompt();
        assert!(p.contains("_orchestrator/task.md"), "reads the task file");
        assert!(p.contains("jj describe"), "commits via jj describe");
        assert!(p.contains("jj commit"), "commits via jj commit");
        assert!(p.contains("_orchestrator/result.md"), "writes result.md");
        assert!(p.contains("_orchestrator/DONE"), "writes the DONE sentinel");
        assert!(
            p.to_lowercase().contains("last"),
            "DONE must be written LAST"
        );
        // Isolation reminders.
        assert!(p.contains(".orchestrator/"), "warns off the private dir");
        assert!(p.to_lowercase().contains("push"), "forbids pushing");
    }

    #[test]
    fn render_prior_findings_writes_empty_file_then_jsonl() {
        use crate::artifacts::{Finding, Findings, Location, Severity, ARTIFACT_DIR};
        let tmp = tempfile::tempdir().expect("tempdir");
        let ws = tmp.path();

        // No findings → an existing but zero-byte input (the first round).
        render_prior_findings(ws, &[]).expect("render empty");
        let path = ws.join(ARTIFACT_DIR).join(PRIOR_FINDINGS_FILE);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "");

        // With findings → one jsonl line per finding, re-parsing to the same set.
        let finding = Finding {
            severity: Severity::High,
            location: Location::parse("src/lib.rs:1").expect("location"),
            claim: "greeting_head hides a get_unchecked call".to_owned(),
            evidence_files: vec!["src/lib.rs".to_owned()],
        };
        render_prior_findings(ws, std::slice::from_ref(&finding)).expect("render findings");
        let body = std::fs::read_to_string(&path).expect("read");
        let reparsed = Findings::parse(&path, &body).expect("reparse delivered findings");
        assert_eq!(reparsed.findings(), std::slice::from_ref(&finding));
    }

    #[test]
    fn task_from_issue_folds_title_and_description() {
        assert_eq!(
            task_from_issue("Add widget", Some("Do the thing")),
            "# Add widget\n\nDo the thing"
        );
        assert_eq!(task_from_issue("Add widget", None), "# Add widget");
        // Whitespace-only description folds to title-only.
        assert_eq!(task_from_issue("T", Some("   ")), "# T");
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
    fn builder_produces_a_claude_command_with_the_implementer_policy() {
        let cmd = worker_command(&root(), &ws(), "do the thing", DEFAULT_MAX_TURNS);
        let spawn = match cmd {
            WorkerCommand::Claude(s) => s,
            _ => panic!("Implementer builder must produce a Claude command"),
        };
        assert_eq!(spawn.role, WorkerRole::Implementer);
        assert_eq!(spawn.allowlist, allowed_tools());
        assert_eq!(spawn.denylist, disallowed_tools());
        assert_eq!(spawn.system_prompt, system_prompt());
        assert_eq!(spawn.max_turns, 80);
        // The Implementer sandbox binds the repo .jj/ + .git/ (committing role).
        assert!(spawn.mounts.has_jj());
        assert!(spawn.mounts.has_git());
    }

    #[test]
    fn to_argv_is_a_valid_bwrap_nix_claude_invocation() {
        let cmd = worker_command(&root(), &ws(), "do the thing", DEFAULT_MAX_TURNS);
        let spawn = match cmd {
            WorkerCommand::Claude(s) => s,
            _ => unreachable!(),
        };
        let argv = spawn.to_argv(&ws(), &test_host());

        // bwrap prefix.
        assert_eq!(argv[0], "/nix/store/hash-bubblewrap/bin/bwrap");
        // nix-shell after the separator, entering <ws>/shell.nix and --run claude.
        let sep = argv.iter().position(|a| a == "--").expect("separator");
        assert_eq!(argv[sep + 1], "/nix/store/hash-nix/bin/nix-shell");
        assert_eq!(argv[sep + 3], "--run");
        let run = &argv[sep + 4];
        assert!(run.starts_with("claude "), "run string: {run}");
        // Headless `-p` bootstrap so the worker actually starts (finding #4).
        assert!(run.contains("-p "), "must launch headless with -p: {run}");
        assert!(run.contains("--permission-mode default"));
        assert!(run.contains("--max-turns 80"));
        assert!(run.contains("--allowed-tools"));
        // The belt-and-suspenders deny list rides through too.
        assert!(
            run.contains("--disallowed-tools"),
            "deny list must ride through: {run}"
        );
        assert!(run.contains("jj abandon:*"), "deny list content: {run}");
        // REQ-4: never the dangerous skip.
        assert!(
            !run.contains("--dangerously-skip-permissions"),
            "REQ-4: must never pass --dangerously-skip-permissions"
        );
        // The allowlist rode through (quoted; it contains spaces + parens).
        assert!(
            run.contains("jj commit:*"),
            "allowlist in run string: {run}"
        );
        // The blocked verbs are not in the ALLOWLIST (that would permit them),
        // but they DO appear in the deny list (`--disallowed-tools`), which is
        // the correct posture — cleanly refused, not silently permitted.
        assert!(
            !allowed_tools().contains("jj abandon"),
            "blocked verb must not be allowlisted"
        );
        assert!(
            !allowed_tools().contains("git push"),
            "blocked verb must not be allowlisted"
        );
        assert!(
            run.contains("git push:*"),
            "deny list carries git push: {run}"
        );
    }
}
