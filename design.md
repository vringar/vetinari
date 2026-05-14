# Orchestrator for Verification-Driven Development

A design for a multi-agent VDD workflow that runs deterministically, survives arbitrary host shutdown, and treats inference as the metered resource (compute is local).

---

## Goals

1. **Deterministic phase enforcement.** A multi-stage workflow per issue: refine → graph → implement → static-QA → adversary → (loop) → converge → PR. The agent never chooses what stage it is in; the orchestrator does.
2. **Crash-safe.** All state on disk in the project's working tree. Host can be shut down at any moment; resuming picks up where things left off.
3. **Sandboxed execution.** Agents run in `claude-sandbox` (bwrap) with explicit allowlists, not `--dangerously-skip-permissions`. Recent Claude Code can prompt even in bypass mode, freezing sessions a headless orchestrator can't recover from.
4. **Cheap-compute gating.** Formatters, linters, tests, pre-commit run between agent invocations and gate further inference. Inference runs against limits; static QA does not.
5. **Cross-machine.** Laptop files issues; desktop runs the orchestrator; both stay in sync.
6. **Headless observability.** Status visible via files in shared mounts (`crosslink tui`, `events.jsonl`, `heartbeat-*.json`), never via attaching to a running TTY.

## Non-Goals

- Tree-shaped agent hierarchy with supervisors (flat per-issue is enough).
- Replacing crosslink's tracker — it's the substrate, not extended.
- Building our own issue tracker.
- Cross-host distribution of the orchestrator itself (single orchestrator, single host).

---

## Substrate: crosslink as a thin issue store

**Use:**
- `crosslink issue list --json` — poll source
- `crosslink issue show` / `comment` / `label` / `unlabel` / `update` / `block` / `close`
- `crosslink session action "..."` — breadcrumbs
- `crosslink knowledge search` / `show` — cross-issue memory
- The hub branch (`crosslink/hub`) for cross-machine sync

**Do not use:**
- `crosslink kickoff` / `swarm` — tmux + git-worktree assumptions, tmux-attached watchdog, wrong topology for VDD.
- `crosslink locks` — single orchestrator owns dispatching; no race.
- Crosslink's deployed PreToolUse hooks for *workflow* enforcement — they're voluntary and bypass-mode-defeatable. We do enforce via the orchestrator. We *do* keep `heartbeat.py` and `post-edit-check.py` (useful, not load-bearing).

Init: `crosslink init --solo`. Skip `agent init` on machines that aren't going to sync to a hub. For machines that sync, generate the agent key **on the host once**, not inside any sandbox — keys go to `.crosslink/keys/` under the project bind, where they persist.

---

## Architecture

```
┌────────────────────────────────────────┐
│  Orchestrator (long-running, headless) │
│   • Refinement pump                    │
│   • Build pump                         │
│   • Spawner (claude-sandbox + jj)      │
│   • QA gate runner                     │
│   • Watchdog (heartbeat monitor)       │
│   • crosslink write authority          │
└─────┬───────────────────────┬──────────┘
      │                       │
      ▼                       ▼
┌────────────────┐    ┌──────────────────────────────┐
│  crosslink     │    │  claude-sandbox worker       │
│  • issues.db   │    │  • bwrap + jj workspace      │
│  • hub branch  │    │  • RO mount of .crosslink/   │
│  • knowledge   │    │  • RW mount of its workspace │
└────────────────┘    │  • NO .orchestrator/ mount   │
                      └──────────────────────────────┘
```

The orchestrator has full access to everything. Workers see only their workspace plus a curated RO view of crosslink.

---

## State machine (per issue)

```
[no phase label]                        ← user filed an issue
  └→ phase:refining                     ← refinement agent running
       └→ phase:graphed                 ← deps/subissues recorded, ready to build
            └→ phase:implementing       ← Implementer running (fresh agent every entry)
                 └→ phase:qa-gate       ← orchestrator runs static QA on the new commit
                      ├→ PASS → phase:adversary-review
                      └→ FAIL → phase:implementing (fresh agent, fail output as input)
                 └→ phase:adversary-review  ← Adversary running (fresh context, no .jj)
                      ├→ findings exist → phase:implementing (fresh agent, findings as input)
                      └→ no findings → check convergence policy
                            ├→ not yet converged → phase:adversary-review (next round)
                            └→ converged → phase:converged
                 └→ phase:converged
                      └→ phase:pr-open  ← orchestrator opens PR via gh
```

**Visible state** (in crosslink): `phase:*` labels, `round:N` label, typed comments.

**Authoritative state** (in `.orchestrator/state.db`, never seen by workers): active spawns, heartbeat tracking, convergence counters, round-N diff hashes, deadlines, queue. The crosslink labels are a *presentation layer* for agents and humans; the orchestrator's decisions read from `state.db` plus workspace artifacts. If a worker mutates labels, the orchestrator notices but its next-action decision is unaffected.

---

## Two independent pumps

Both poll `crosslink issue list --json` on a short interval (~5s). They never block each other.

### Refinement pump
- Watches issues with no `phase:*` label.
- Spawns a Refiner: explores the codebase, writes a dependency graph via `crosslink subissue` and `crosslink issue block`, transitions the issue to `phase:graphed`.
- Output is the "scaffold" idea from ExoMonad adapted to issue space: the dependency graph is the unfold step.

### Build pump
- Watches issues with `phase:graphed` AND no open blockers (equivalent to `crosslink issue ready`).
- Drives the per-issue state machine through implement / QA / adversary cycles to PR.

Refining one issue and building another in parallel is the common case.

---

## Agent spawn contract

Every spawn:

```
claude-sandbox --project-dir "$WORKSPACE_PATH" -- \
  claude \
    --permission-mode default \
    --allowed-tools "$ALLOWED_TOOLS" \
    --append-system-prompt "$ROLE_PROMPT" \
    --max-turns "$MAX_TURNS" \
    <<< "$TASK_PROMPT"
```

**Invariants:**
- `WORKSPACE_PATH` was created with `jj workspace add` (when applicable) before spawn; torn down after.
- `--permission-mode default`, never bypass. Allowlist sized so no prompt should ever fire — if the agent needs a tool not on the allowlist, it gets a clean error and fails the phase loudly.
- **Fresh context every phase.** Implementer at round N+1 is a brand-new agent given (worktree, prior Adversary findings file). No memory from earlier rounds. Eliminates the "defending my work" incentive in the convergence question.
- Agent commits at end of work (Implementer only) and exits. Workers do not call `crosslink` to mutate state — they write output artifacts; the orchestrator translates artifacts → crosslink writes.

---

## Per-role mount surface

Workers see only what their role needs. The orchestrator decides what to bind into each role's sandbox.

| Mount | Refiner | Implementer | Adversary |
|---|---|---|---|
| Workspace dir (RW project bind) | yes | yes | yes |
| Parent `.jj/` | **no** | yes | **no** |
| Parent `.git/` | no | yes (if used) | no |
| `.crosslink/` (RO) | yes | yes | yes |
| `.orchestrator/` | **no** | **no** | **no** |
| Parent project source (read) | yes (via separate RO bind for exploration) | n/a (inside its workspace) | n/a |
| Pre-rendered `_orchestrator/` inputs | no | no | **yes** (diff.patch, log.txt, prior_findings.json) |

Three reasons for differentiating:

1. **`.orchestrator/` is invisible to all workers.** Physical isolation, not RBAC. No inode in the worker's namespace ⇒ nothing to read or mutate.
2. **`.crosslink/` is RO for workers.** Reads work (memory, cross-reference, knowledge lookup); writes fail with "database is read-only." Workers cannot push to the hub branch. Knowledge cannot be mutated by workers. Auto-hydration on other machines stays orchestrator-only.
3. **Only the Implementer gets `.jj/`.** jj's operation log is shared globally across workspaces — anyone with RW `.jj/` can `jj abandon`, `jj op undo`, or `jj workspace forget` on workspaces they don't own. The Adversary doesn't need to commit, so it doesn't get `.jj/` at all. Its diff/log/history are pre-rendered into `_orchestrator/`.

### Adversary inputs in `_orchestrator/`

Before spawning an Adversary, the orchestrator drops these into the workspace:

```
.workspace/adv-42-r3-<uuid>/
  ...all files at the Implementer's committed state...
  _orchestrator/
    diff.patch          — jj diff of this Implementer round vs prior round
    log.txt             — jj log -r ... for this issue's chain
    prior_findings.json — every prior round's findings on this issue
    task.md             — the Adversary's role prompt
```

The Adversary reads `_orchestrator/diff.patch` instead of running `jj diff`. It can write throwaway tests, run `cargo test`, etc., on plain files. The entire workspace gets `rm -rf`'d when the phase ends. No `.jj/` ⇒ no version-control escape, no commit, no propagation.

### Implementer jj allowlist

The Implementer needs `.jj/` (to commit). Block destructive operations via Bash allowlist prefixes:

**Allowed:** `Bash(jj describe:*)`, `Bash(jj commit:*)`, `Bash(jj new:*)`, `Bash(jj diff:*)`, `Bash(jj show:*)`, `Bash(jj log:*)`, `Bash(jj status:*)`, `Bash(jj files:*)`, `Bash(jj squash:*)`, `Bash(jj split:*)`

**Blocked (omit from allowlist):** `jj abandon`, `jj op undo`, `jj op restore`, `jj workspace forget`, `jj workspace add`, `jj workspace list`, `jj edit`, `jj git push`, `jj git fetch`, `jj rebase`

With `--permission-mode default`, anything not on the allowlist returns an error to the agent rather than executing.

`jj op log` is global — the Implementer can *see* operations from other workspaces. Reading is fine; it can only mutate via allowlisted commands.

---

## Worker output via artifacts (not crosslink writes)

The orchestrator is the only entity that writes to crosslink. Workers produce structured files in their workspace; the orchestrator translates them into crosslink mutations after the phase ends.

| Worker | Output artifacts |
|---|---|
| Refiner | `_orchestrator/subissues.json` (list of subissues to create with deps), `_orchestrator/summary.md` |
| Implementer | Code commits via jj + `_orchestrator/result.md` (what changed, what it addressed from prior findings) + `_orchestrator/progress.jsonl` (append-only breadcrumbs during execution) |
| Adversary | `_orchestrator/findings.jsonl` (one finding per line: `{severity, location, claim, evidence_files}`), throwaway test code in workspace (discarded) |

Orchestrator post-processing:

- Parses each artifact against a schema (~50 lines per type).
- Writes the corresponding crosslink comments with its own attribution (`--kind result` from Implementer, `--kind blocker` per Adversary finding, `--kind observation` for Refiner summary).
- Records the worker's role and round in the comment metadata for the audit trail.
- For long-running phases, the orchestrator can tail `_orchestrator/progress.jsonl` and stream breadcrumbs to crosslink in near-real-time (signed by orchestrator, attributed to worker role).

Property: regardless of what a worker does in its workspace, it cannot affect crosslink state directly. Every crosslink mutation carries the orchestrator's signature. The audit trail is uniform.

---

## QA gate

After every Implementer commit, the orchestrator runs `.orchestrator/static_qa.sh` against the workspace. Auto-detect what's configured per project (template — copy and adjust per project root):

```bash
set -e
[ -f .pre-commit-config.yaml ] && pre-commit run --all-files
[ -f Cargo.toml ] && cargo fmt --check && cargo clippy -- -D warnings && cargo test
[ -f package.json ] && npm run lint && npm test
[ -f pyproject.toml ] && ruff check && pytest -q
```

Each non-zero exit captures: tool name, exit code, last ~50 lines of output. The orchestrator posts this as a `--kind blocker` comment and feeds it as input to the next Implementer spawn.

**Hard rule:** the agent never decides QA pass/fail. The orchestrator owns the verdict by exit code, deterministically.

---

## Convergence — configurable per project (and per issue)

```toml
# .orchestrator/config.toml
[convergence]
mode = "n-rounds"       # "n-rounds" | "judge" | "human"
n_rounds = 2            # for n-rounds: terminate after N consecutive empty rounds
judge_after = 4         # for judge: try n-rounds first, escalate Judge agent after N
human_timeout = "24h"   # for human: how long to park at phase:awaiting-human-arbitration
```

Choose by stakes: throwaway scripts → `n-rounds, N=1`; production library → `judge`; compliance-relevant → `human`. Per-issue override via a label (`convergence:judge`) takes precedence over the project default.

**Convergence is detected by the orchestrator, not declared by the Implementer.** The original VDD writeup has a hole here ("Builder declares Sarcasmotron is hallucinating") — that's a fox-in-henhouse termination criterion. By making the system detect convergence from artifact-diff-emptiness + QA-pass, the Builder is never the judge.

A Judge agent (when escalated) gets fresh context, full diff, both prior transcripts, and a prompt of "is this finding actionable or not?" — same fresh-context principle as the Adversary.

---

## Per-issue parallelism + concurrency budget

Multiple issues progress simultaneously. Each active agent has its own `(issue_id, phase, round, uuid)` tuple and its own jj workspace.

```toml
# .orchestrator/config.toml
[budget]
max_concurrent_agents = 4
max_per_role = { implementer = 2, adversary = 2, refiner = 1 }
poll_interval_ms = 5000
heartbeat_threshold_s = 120  # stale → kill + respawn
```

When the cap is hit, the pump waits at the "pick next issue" step — never queues at the agent level. This keeps inference cost bounded even with many ready issues.

Workspaces are named `.workspace/<phase>-<issue>-r<round>-<short-uuid>/`. The uuid permits multiple Adversary attempts on the same round without name collisions (e.g., a Judge escalation alongside the regular Adversary).

---

## Failure handling + watchdog

**Heartbeat:**
- Every spawned agent writes `<workspace>/_orchestrator/heartbeat.json` every ~10s via a PostToolUse hook (steal `heartbeat.py` from crosslink resources, point it at the workspace path).
- Orchestrator iterates all active heartbeats each tick.
- Stale > threshold → kill the sandbox process group, `jj workspace forget` + delete workspace, transition the issue back to its prior phase, log to `events.jsonl`. Then re-spawn fresh.

**No "try to recover."** Fresh context for the replacement = no inherited confusion. The workspace is already gone; the next spawn starts clean.

**Stuck permission prompt:** with `--permission-mode default` and a tight allowlist, an unauthorized tool returns an error to the agent rather than prompting. No silent freeze possible — either the agent handles the error and continues, or it fails the phase, which the orchestrator detects and respawns.

**Half-initialized workspace:** the spawn helper always runs `jj workspace forget` + `rm -rf` for an issue's workspace path *before* a fresh spawn, not only on success. Eliminates the orphan-worktree bug class.

---

## Observability

Three artifacts cross the sandbox boundary (everything inside the project bind):

| Artifact | Purpose | Read from outside with |
|---|---|---|
| `.orchestrator/heartbeat-<workspace-uuid>.json` | Current operation + last progress timestamp per active agent | `cat` / `jq` |
| `.orchestrator/events.jsonl` | Append-only: spawn, phase transition, QA result, watchdog kill, convergence | `tail -f \| jq .` |
| `.crosslink/issues.db` (typed comments) | Human-readable narrative trail | `crosslink tui`, `crosslink issue show <id>` |

**Outside the sandbox**, observability is:
- `crosslink tui` for issue browsing (phases visible as labels)
- `tail -f .orchestrator/events.jsonl | jq .` for live machine state
- `jq . .orchestrator/heartbeat-*.json` for "what is each agent doing right now"
- Launch a second `claude-sandbox` into the same project for deep inspection — same project bind, separate isolation

The orchestrator surfaces state. The orchestrator never *runs* anything you can't see from this triplet.

---

## Cross-machine sync (laptop ⇄ desktop)

Crosslink syncs by event-sourcing over a git branch:

```
laptop                                          desktop
  crosslink issue create "fix login"     ─push─►  git fetch
       │                                                │
       events committed to                         crosslink sync (or lazy auto-hydration)
       crosslink/hub branch                             │
       │                                                │
       pushed to origin ────────────────►          local issues.db gains the new issue
                                                        │
                                                        orchestrator's poll loop picks it up
```

The local `issues.db` is a *materialized view*; the canonical state is the `crosslink/hub` branch on the git remote. `crosslink/knowledge` works the same way for shared knowledge pages.

**Setup:**

- Pick a git remote both machines can reach (private GitHub/Gitea/self-hosted repo). The hub branch and the knowledge branch live alongside code branches.
- On each host: `crosslink agent init <hostname>` from a **normal shell**, not inside a sandbox. Keys land in `.crosslink/keys/<hostname>_ed25519` under the project bind, where they persist across sandbox runs.
- Approve each other's keys: laptop `crosslink trust approve desktop`, desktop `crosslink trust approve laptop`.
- Run `crosslink daemon start` on each machine so writes auto-push and the orchestrator sees new issues without a manual sync.

**SSH key trap to avoid:** never run `crosslink agent init` *inside* a sandbox — `$HOME` is tmpfs, but more importantly the key would land in `.crosslink/keys/` and the orchestrator would then write a `user.signingkey = .crosslink/keys/...` to git config. Generate keys on the host first; sandboxed processes inherit access via the project bind (and SSH_AUTH_SOCK forwarding for signing, if needed for non-agent-key operations).

---

## Layout

```
project-root/
  .jj/                                jj repo
  .workspace/                         ephemeral, one per active worker
    refine-42-<uuid>/
    implement-42-r3-<uuid>/
    adversary-42-r3-<uuid>/
      _orchestrator/                  inputs (Adversary) / outputs (all roles)
        diff.patch
        log.txt
        prior_findings.json
        task.md
        result.md                     written by Implementer
        findings.jsonl                written by Adversary
        progress.jsonl                append-only breadcrumbs (any role)
        heartbeat.json                from PostToolUse hook
  .crosslink/                         tracker (orchestrator: RW; workers: RO)
    issues.db
    keys/<hostname>_ed25519           generated on host, not in sandbox
    .hub-cache/                       worktree of crosslink/hub branch
  .orchestrator/                      orchestrator-private (workers cannot see)
    config.toml                       budgets, convergence mode, role allowlists
    static_qa.sh                      per-project QA gate
    state.db                          authoritative state machine
    events.jsonl                      append-only event log
    heartbeat-<workspace-uuid>.json   per-active-worker (also mirrored in workspace)
    prompts/
      refiner.md
      implementer.md
      adversary.md
      judge.md
  .claude/
    settings.json                     permission mode + allowlist per role
    hooks/
      heartbeat.py                    PostToolUse, throttled (steal from crosslink)
      post-edit-check.py              optional stub detection (steal/adapt)
```

---

## Implementation phases

1. **MVP loop.** Single pump, hardcoded "implement → QA" with no Adversary. Verify the spawn + sandbox + jj workspace + artifact pipeline works end-to-end on a toy project.
2. **Adversary cycle.** Add Adversary phase (no `.jj`, pre-rendered inputs), fresh-Implementer-on-feedback, n-rounds convergence detection.
3. **Refinement pump.** Decoupled from build pump, populates dependency graph + subissues.
4. **Watchdog.** Heartbeat monitoring, kill + respawn on stale, workspace cleanup.
5. **Convergence escalation.** Judge mode, then human mode. Per-issue overrides.
6. **Cross-machine.** Verify hub-branch sync end-to-end with daemon running on both hosts.

Each phase is independently shippable. Stop at (2) if convergence is good enough that refinement and watchdog don't pay for themselves yet.

---

## Pitfalls to avoid (lessons learned)

- **Don't use `--dangerously-skip-permissions`.** Recent Claude Code can prompt even in bypass mode; the prompt freezes a headless session with no way to recover from outside. Enumerate tools.
- **Don't mount host multiplexer sockets into the sandbox.** Cross the boundary with artifacts (files in shared mount), not handles (sockets, PTYs).
- **Don't trust the agent's self-assessment of QA.** Orchestrator owns the verdict by exit code.
- **Don't try to recover a stuck agent.** Kill + respawn with the same inputs. Fresh context has no ego.
- **Don't write to `~/.ssh/` from inside the sandbox.** Tmpfs; doesn't persist. Generate keys on the host.
- **Don't let workers write to crosslink directly.** Auto-hydration on other machines + event-sourced model means any worker write propagates everywhere. Workers produce artifacts; orchestrator translates.
- **Don't mount `.jj/` into workers that don't need to commit.** jj's operation log is shared across workspaces; `jj abandon` and `jj op undo` are global. Adversary doesn't need `.jj/`; don't give it.
- **Don't run `crosslink agent init` inside a sandbox.** Run it on the host; the keys persist under the project bind.
- **Don't rely on labels for orchestrator state.** Labels are presentation for agents. Authoritative state lives in `.orchestrator/state.db`.

---

## Open questions

- **Convergence escalation details:** Judge agent's prompt and what counts as "actionable" need iteration with real workloads.
- **Per-issue parallelism in practice:** two issues both in `implementing` with independent jj workspaces — should be fine, but verify resource contention isn't a problem on the first real project.
- **Hook reuse from crosslink:** copy `heartbeat.py` and `post-edit-check.py` as-is for v1; rewrite if they grow unwanted behavior.
- **Refiner allowlist scope:** Refiners need to explore the codebase. RO mount of `..` (parent project) or a separate `--ro-bind` of `<repo>/`? Probably the latter, scoped explicitly.
- **Knowledge writes:** the orchestrator owns knowledge writes too. Workers can read knowledge for memory; they emit `_orchestrator/knowledge_proposals.md` if they want to contribute, and the orchestrator decides whether to publish.
