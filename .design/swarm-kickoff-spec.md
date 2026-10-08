# Spec: Swarm kickoff — the two gaps between the VDD executor and a live 5-node federation

> DESIGN/ANALYSIS. Read-only survey of the tree at the time of writing + the threat model (`THREAT_MODEL_WORKER_ISOLATION.md`). Grounded in code at `file:line`. No source edited.

> **Update:** the socket-based federation transport this spec originally designed (embedded server, answer-back state machine, inbound approval gate) was removed from the codebase and is no longer part of the plan. Cross-repo coordination is now via the message board (`board` CLI) plus a human-started comms-agent session (skill-driven, outside the orchestrator) that translates board messages into graphed crosslink issues. Sections below that described the removed transport are condensed to a note; the worker follow-up proposals (§1.6) and the section-chief / `vetinari` CLI work (GAP 2) are unchanged and still apply.

## Goal

Get from today's **per-repo executor** (one headless pump driving locally-filed `phase:graphed` issues to `main`) to a **human-supervised 5-node federation** where nodes can request work from each other (via the message board and a comms agent) and a human/section-chief can see and steer each node. Name every increment; keep the threat model's trust boundary enforced in the design, not assumed.

## Current state (grounded)

- The orchestrator is a **single-threaded, synchronous, tokio-free** poll loop: `main.rs:136-145` (`tick(); sleep; loop`), one binary only (`orchestrator/Cargo.toml:68`). Root `Cargo.toml` documents the no-async choice as deliberate (cited in the review, B1).
- Pump pickup = **open issue + `phase:graphed` label + no open blockers** (`pump.rs:8-9`, `GRAPHED_LABEL` `pump.rs:156`, pickup scan `pump.rs:463-494` over `list_by_label`/`list_issues`). Unphased issues are ignored.
- **Blockers are the DAG.** `open_blockers` (`crosslink_api/src/repo.rs:178`) is the edge set; a graphed issue with open blockers is held. "Seed a graphed DAG" literally means: create issues, wire blocker edges, apply `phase:graphed`.
- Phase machine: `Graphed → Implementing → QaGate → AdversaryReview → Converged → Landing → Merged | PrOpen`; parked `AwaitingHumanMerge`, `OrchestratorError` (`state.rs:102-123`). `is_drivable = {Graphed, Implementing, QaGate}` (`state.rs:143`). `PhaseSubstate` already exists as a free column (`state.rs:151-174`, schema `state.rs:232`).
- Landing: local FF-guarded bookmark advance (`land_local`, `landing.rs:145`) OR remote push+PR when crosslink's `tracker_remote` is set (`land_remote`, `landing.rs:416-`; `crosslink_api tracker_remote()` `repo.rs:239`). Mode is **global**, not per-issue.
- **The threat model's P0 is CLOSED.** QA now runs inside a hermetic bwrap sandbox — `--unshare-net`, creds/`GH_TOKEN`/pin stripped, grader executed under the worker mount matrix (`qa.rs:11-48`, `SandboxHost::qa_mounts`). This is what moves *trusted-origin* auto-landing to CONDITIONAL-GO. It does **nothing** for intent-level attacks (T2 deferred payload, T4 prompt-injected LLM gate) — those are why *untrusted/inbound* stays HARD NO-GO.
- crosslink_api surface: `read_issue`, `list_by_label`, `open_blockers`, `list_comments`, `tracker_remote`, `comment_write(kind,…)` (kinds validated by crosslink — `repo.rs:286-313`), `label_add`/`label_remove`, `sign`.
- Recovery runs once before the loop: `recover()` (`recovery.rs:338`, called `main.rs:109`).
- AC-24 lint bans `Command::new("jj|git|gh|crosslink|zellij")` via `syn`; exempt crates `xtask`, `zellij_host` (`xtask/src/lint.rs:30,42`).
- **Steering surface today = `just graph` only** (a wrapper over `crosslink issue blocked/ready`, `justfile:120`). Nothing exposes pump phase, substate, or workers. There is **no `vetinari` CLI** and **no `vetinari` skill** (confirmed: single bin, no skill dir).

Net: GAP 1 (cross-repo ingestion) is now handled outside the orchestrator by the message board + comms agent. GAP 2 (section chief + `vetinari` skill + directive decomposition) is barely designed; this spec designs it from scratch.

---

## GAP 1 — cross-repo requests (superseded)

The original design for this gap (an embedded federation server in the orchestrator, an answer-back state machine, and a `phase:awaiting-inbound-approval` land gate for untrusted inbound issues) was removed.
Cross-repo coordination now runs over the message board (`board` CLI): a human-started comms-agent session, driven by a skill and not part of the orchestrator, translates board messages into graphed crosslink issues.
The orchestrator therefore has no inbound path of its own: every issue it drives is graphed by a human or the section chief through the normal seeding protocol, and the threat model's rule that untrusted-origin work must not auto-land is enforced by that human graphing step rather than by an orchestrator-side gate.
Coordination stays at the issue boundary, never inside a running worker (a sandboxed worker asking a peer mid-task would break hermeticity, REQ-8).
Nothing authors another node's graph automatically: the pump executes DAGs, it does not generate them, so the honest description is 5 executors plus a message bus plus human/chief-authored graphs and human/chief-initiated cross-repo requests.

### 1.6 Worker follow-up work — propose, never author (REQ-SWARM-2)

A worker driving an issue (local or cross-repo) routinely *discovers* follow-up work: "we also need to parse sub-record Y", "X is blocked on recovering enum Z". That discovery must not be lost — but a worker must **never write the graph**. Workers get crosslink **read-only** (already enforced: the per-role mount matrix binds `<root>/.crosslink/` RO for every role, `spawn.rs:426-459`). Three walls forbid a direct write:

1. **Trust / graph-integrity.** A worker on untrusted-origin work that can create issues + blocker edges can inject arbitrary backlog, build a block-cycle or block-bomb (DoS the DAG), or shape the graph so malicious work is prioritized or auto-landed — the T4 injection surface the threat model keeps on the strictest gate. The graph is the one lever that decides what runs and what lands; an untrusted agent never gets it.
2. **Single-writer invariant (REQ-3).** Pickup is DAG-derived (`open_blockers`, `repo.rs:178`) and recovery assumes the graph is authored out-of-band. A worker writing crosslink is a second writer racing the pump and makes the graph self-modify mid-run — recovery can no longer re-derive deterministically.
3. **Runaway.** Free self-spawned follow-ups let the backlog explode unbounded; the pump would chase an ever-growing self-authored graph no human can keep up with — the opposite of verification-driven.

**The mechanism (propose-don't-commit).** Workers already speak to the orchestrator through crosslink comment *kinds* (`--kind result`/`--kind blocker`). Add **`--kind followup`** (or a structured `proposed_followups` block in the worker's output): title + rationale + suggested blocker edges + a *sketch* of the verifiable gate. It rides the existing worker→orchestrator result channel the pump already reads — **no new write path out of the sandbox.** The orchestrator records these as **proposals** (a `followup:proposed` label / draft), never active graphed issues. **Promotion is the single writer's job, gated:**
- *Trusted-origin (local) node work:* the chief/human promotes, or a chief-preapproved policy auto-promotes within a bounded research area (the human still authored the area and the gate).
- *Untrusted-origin (from another repo):* promotion is always human-gated.
- *Cross-node* ("need X from repo B") is **not** a worker write either — it becomes a message-board post by a human or the comms agent, which the other repo's comms agent translates into an issue that its human gates.

Net: the graph grows only through the trusted single writer, worker discoveries are first-class (nothing lost), and "chief authors the graph, pump executes it" holds. Promotion tooling is a chief/`vetinari`-skill concern (step 2) plus the human gate.

---

## GAP 2 — section chief + `vetinari` skill + directive decomposition

### 2.1 The section chief is a plain interactive Claude Code — not a vetinari worker

**Argue the pragmatic answer: plain CC, on the host, in the repo dir.** vetinari workers are ephemeral, bwrap-sandboxed, hermetic, fresh-context, headless (no stdin) — every property is the *opposite* of a long-lived, human-facing, stateful advisor. Managing the chief as a worker would (a) break hermeticity, (b) put a human-conversation agent inside a stdin-less sandbox where `--permission-mode default` wedges on every prompt (`roles/mod.rs:44-50`), and (c) give a human's interlocutor the worker mount matrix instead of the repo it needs to read. So the chief runs at the **orchestrator's trust level** (host, unsandboxed), exactly like the human it speaks for.

What it **reads**: `.crosslink/issues.db` (issues, comments, labels, blocker DAG), `state.db` (phase/substate/round/workers — *read-only*), `events.jsonl`, the worktrees under the workspace root, the pump's live panes (`zellij attach vdd-orchestrator`, `main.rs:87-96`).

What it **does** (all through existing write channels, preserving single-writer): seed issues + wire blocker edges + apply `phase:graphed` (via `crosslink issue`), write per-issue `.orchestrator/static_qa.sh`, answer the human, and.

What it **lacks today:** everything except `just graph`. It cannot see pump phase (that lives in `state.db`, not crosslink), and cannot inspect a worker. That is the missing interface below.

### 2.2 A read-only `vetinari` query CLI (the surface the skill calls)

New read subcommands, **read-only against `state.db` + `events.jsonl`**, joined with crosslink for the DAG. Read-only is the whole point: writes stay through crosslink so the single-writer invariant (REQ-3) holds and the chief can never corrupt orchestrator state. Ship as subcommands on the existing bin (`orchestrator status …`) or a thin second bin `vetinari`; second bin reads cleaner for the skill and the zellij pane title.

```
vetinari status [--issue N]     # phase, substate, round, empty_round_streak, landing_retry (state.rs row)
vetinari graph                  # DAG: each issue's crosslink blockers × its state.db phase — the real "what's blocked on what"
vetinari workers                # active_workers rows: role, round, workspace, pid, last_heartbeat
vetinari events [--issue N] [--tail]   # events.jsonl slice (spawn/transition/qa_result/…)
```

Load-bearing constraint: the **running orchestrator holds `state.db` open.** The CLI must open a **second read-only connection** under the same WAL + busy-timeout discipline. Flag: if `state.db` is not WAL, a reader can block the pump — verify the journal mode before shipping this.

`vetinari graph` is the one genuinely new synthesis: today `just graph` shows crosslink `ready`/`blocked` (dependency edges) but is **blind to execution phase**. Joining `open_blockers` (`repo.rs:178`) with the `state.db` phase gives the chief the first real "swarm status" view of its node.

### 2.3 The `vetinari` skill

A `SKILL.md` (none exists) that documents, for the section chief:
1. **Introspect** — the `vetinari status/graph/workers/events` commands above, with worked examples.
2. **Steer** — the *seeding protocol*: how to file a graphed issue DAG (`crosslink issue new`; wire blockers; author `.orchestrator/static_qa.sh`; apply `phase:graphed` last so the pump doesn't pick up a half-seeded issue), how to reprioritize (add/remove blockers), how to park (remove `phase:graphed`).
3. **Cross-repo requests** — a pointer to the message board and the comms-agent workflow (the orchestrator itself has no federation path).
4. **The gate discipline** — 2.4 below: every graphed issue MUST carry a deterministic `static_qa.sh`, and what that means for RE.

The skill is *documentation + a thin CLI*, not new orchestrator behavior — it is the cheapest high-leverage increment and should ship first.

### 2.4 Directive → graphed-issue decomposition — the hardest conceptual gap

"Seed with research directives and autonomously organize" collides with a hard fact: **vetinari executes graphs; it does not author them, and it cannot verify a task that has no deterministic gate.** `phase:graphed` pickup requires a committed `.orchestrator/static_qa.sh` that returns pass/fail (`qa.rs`), because convergence and landing are gated on it. "Reverse-engineer subsystem X" has no natural pass/fail.

**Who authors the graph:** the human or the **section chief** (optionally invoking a the-architect-style decomposition agent — the same "design before building" discipline this very file embodies). Not the pump. Recommendation for kickoff: chief drafts the DAG, **human applies `phase:graphed`** (keeps the REQ-16 human-gate; one issue-entry policy shared with cross-repo requests).

**The genuinely hard part — a *verifiable* gate for open-ended reversing.** The only way vetinari can autonomously drive an RE sub-task is to reduce it to an artifact with a checkable invariant. Patterns that work:
- *"Write a parser for format X that round-trips these N captured samples byte-for-byte."* → `static_qa.sh` = run the parser on committed fixtures, assert byte-exact round-trip.
- *"Recover struct layout: emit a C header whose `sizeof`/`offsetof` match these ground-truth probe values."* → gate compiles the header + asserts constants.
- *"Reach basic-block coverage ≥ C on target T under harness H."* → gate runs the harness, asserts coverage.

The gate tests a **proxy artifact**, never "comprehension." Where no such proxy exists — pure exploration, hypothesis generation, "figure out what this blob is" — it is **not a vetinari issue at all.** It is chief/human work, or it produces a report a human grades. Vetinari cannot verify a report, and pretending otherwise is the failure mode this whole design exists to prevent.

**Flag this as the wall:** *defining the gate is itself the research judgment.* The decomposition from fuzzy directive to gate-able sub-issue cannot be fully automated, because choosing "round-trip these samples" as the proxy for "understand the format" *is* the reversing insight. The swarm autonomously drives exactly the fraction of RE that a human/chief has already reduced to a deterministic assertion — no more. This is the honest ceiling on "autonomous research organization," and it should be stated to the stakeholder up front.

---

## Build order (smallest shippable first)

Each step is independently verifiable and independently useful.

1. **`vetinari status`/`graph` read CLI** (2.2). No new deps; read-only over `state.db`+crosslink. *Verify:* run against the live fixture dogfood (AC-11a), see per-issue phase + blocker DAG. Unblocks the chief immediately. *First — highest leverage, lowest risk.*
2. **`vetinari` skill** (`SKILL.md`, 2.3). Docs + seeding protocol wrapping #1. *Verify:* a fresh CC in a repo dir can, from the skill alone, read node state and seed a graphed issue.
3. **(unsupervised only, out of pilot scope) P1 containment** — egress filter (`spawn.rs:1080`), scoped ephemeral creds (`spawn.rs:1069`), per-worker object store (`spawn.rs:445`). Prerequisite to *any* unsupervised operation; see checklist.

Steps 1 and 2 are sequential (the skill wraps the CLI).

---

## Pre-kickoff checklist

### Needed for a **supervised pilot** (human watches; human approves every land)

- [x] **P0 QA sandbox** — done (`qa.rs:11-48`); the reason trusted-origin is CONDITIONAL-GO.
- [ ] Build steps **1–2** above (read CLI, skill).
- [ ] `state.db` confirmed **WAL + busy_timeout** so the read CLI never blocks the pump (§2.2).
- [ ] zellij 5-tab / 2-pane layout script (host-side; a plain zellij layout, not orchestrator code — no AC-24 concern).
- [ ] **At least one worked directive→gate-able-issue decomposition** for the target subsystem (§2.4) — proof the hardest gap is surmountable *for this RE target*, not just in theory. If no proxy gate can be written, the target is not swarm-drivable and the pilot scope must shrink to the part that is.
- [ ] Human-in-loop confirmed on **every** land.

### Additionally needed for **unsupervised** operation

Per the threat model, unsupervised applies **only to locally-authored (trusted-origin) issues within a node.** *Unsupervised auto-land of work originating in another repo stays out of scope* — the threat model calls it HARD NO-GO and warrants a human checkpoint even after all mitigations, so a human graphs every cross-repo-originated issue.

- [ ] **P1 egress filtering** — worker reaches only the Anthropic API (`spawn.rs:1080`, closes T5 exfil path).
- [ ] **P1 scoped ephemeral creds** — not the operator's config-dir RO overlay (`spawn.rs:1069`, T5).
- [ ] **P1 per-worker object store** — no shared `.jj/`+`.git/` RW mount (`spawn.rs:445`, closes T3 corruption / de-worms the federation).
- [ ] **P2 second content gate or per-peer auth** — the LLM adversary is not a sufficient sole gate against T4 injection for anything untrusted.
- [ ] A **track record of supervised runs** before flipping the human out of the trusted-origin land loop.

---

## Threat-model reconciliation

| Recommendation | Trust boundary it respects |
|---|---|
| Section chief = host-level plain CC, not a worker | Chief runs at orchestrator trust level, same as the human; no untrusted agent gets host latitude |
| `vetinari` CLI is **read-only**; writes stay via crosslink | Preserves single-writer (REQ-3); chief cannot corrupt orchestrator state |
| Unsupervised gated on P1(egress/creds/store)+P2 | Directly the threat model's §4/§5 prerequisites; unsupervised auto-land of cross-repo-originated work stays out of scope regardless |

Trusted-origin (locally-authored) issues: CONDITIONAL-GO post-P0, unchanged by this spec. Untrusted-origin (cross-repo) issues: a human graphs each one, so the HARD-NO-GO boundary on unsupervised auto-land holds structurally.

## Open questions

- **`vetinari` as a subcommand of `orchestrator` vs. a second bin?** Second bin is cleaner for the skill/pane-title; subcommand is less packaging. Lean second bin.
- **Is `state.db` currently WAL?** If not, the read CLI (§2.2) needs it before kickoff — verify early.
- **Directive decomposition ownership (§2.4):** chief-only, or a dedicated decomposition agent? Either works; the *human `phase:graphed` gate* is the invariant. What is the concrete first RE target, and can a proxy gate be written for it? — this is the go/no-go for the whole pilot, and it is a domain question, not an engineering one.
