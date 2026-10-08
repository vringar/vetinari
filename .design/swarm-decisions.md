# Swarm kickoff — decision queue

Optimized for a short review window. Each decision: the options, my recommendation, what it blocks, and effort once decided. Skim the table; read only the rows you disagree with. Companion to `.design/swarm-kickoff-spec.md`.

> **Update:** the socket-based federation transport (D2, D8 and the steps built on it) was removed. Cross-repo coordination is now via the message board (`board` CLI) plus a human-started comms-agent session (skill-driven, outside the orchestrator) that translates board messages into graphed crosslink issues. D2 and D8 are void; the other decisions stand.

Legend — **Your call**: genuinely needs you (domain / commitment / trust). **Proceeding**: I've made the reversible call and am building on it; override if wrong.

| # | Decision | My pick | Blocks | Kind |
|---|----------|---------|--------|------|
| D1 | First RE target + can a *verifiable gate* be written for it | (needs you — a narrow round-trippable subsystem) | **live kickoff** | Your call |
| D2 | ~~Unify the federation transport's crosslink onto vetinari's rev~~ | **VOID** — transport removed | — | void |
| D3 | `vetinari` as a second bin vs. `orchestrator` subcommand | Second bin | step 1 | Proceeding |
| D4 | Worker follow-up work: propose-don't-commit vs. direct write | Propose-don't-commit (read-only crosslink + `followup` proposal channel) | step 4–5 | Your call (sanction) |
| D5 | Who authors the issue graph from a directive | Chief drafts the DAG; **human** applies `phase:graphed` | seeding workflow | Proceeding |
| D6 | `auto_graph` in the pilot | Drop it entirely for the pilot | pilot scope | Proceeding |
| D7 | `busy_timeout` on the pump's `state.db` opener | Add it (reader + 2nd writer both need it) | step 1, 5 | Proceeding |
| D8 | ~~Federation server shutdown~~ | **VOID** — transport removed | — | void |

---

## D1 — First RE target + a verifiable gate  *(Your call — this is the pilot go/no-go)*
Vetinari can only autonomously drive a sub-task reducible to a deterministic `static_qa.sh` (pass/fail). It **cannot** drive open-ended "understand this blob" — that's chief/human work producing a human-graded report. So the pilot's whole viability is: **can you name one narrow subsystem whose progress is checkable by a proxy artifact?** Gate patterns that work:
- *Parser round-trip:* "parse format X, byte-exact round-trip these N captured samples" → gate runs it on committed fixtures.
- *Struct layout:* "emit a C header whose `sizeof`/`offsetof` match these ground-truth probe values" → gate compiles + asserts.
- *Coverage:* "reach basic-block coverage ≥ C on target T under harness H" → gate runs harness, asserts.

**What I need from you:** one concrete target subsystem + which gate pattern fits (or "none fits — it's exploration"). If none fits, the pilot shrinks to the gate-able fraction and the rest stays chief/human work. *Defining the gate is itself the reversing insight — it can't be automated.*

## D2 — void
The federation transport this decision unified onto vetinari's crosslink was removed, so there is nothing to unify. The `AC-28a` single-crosslink guard (`xtask check-crosslink`) stays as a general check.

## D3 — Second bin `vetinari`  *(Proceeding)*
A thin second binary `vetinari` in the orchestrator crate reads cleaner for the skill and the zellij pane title than an `orchestrator status` subcommand. Reversible (it's just packaging). **Building on this.**

## D4 — Follow-up work: propose-don't-commit  *(Your call — sanction the model)*
Workers get crosslink **read-only** (already enforced — the sandbox binds `.crosslink/` RO). They **surface** follow-up work as a structured `--kind followup` proposal through the existing result channel; the **single writer (orchestrator)**, gated by the chief/human, promotes a proposal into a real graphed issue. Cross-node follow-up becomes a message-board post by a human or the comms agent, graphed by a human on the far side. Rationale (three walls): (1) an untrusted worker that can author the graph can inject backlog / block-bomb / bias what auto-lands (T4); (2) a second writer to crosslink breaks the single-writer + deterministic-recovery invariant; (3) free self-spawned follow-ups make the backlog explode unbounded. Full write-up in the spec (§1.6). **Confirm this is the model** and I'll build the `followup` kind + promotion path into steps 4–5.

## D5 — Graph authorship: chief drafts, human gates  *(Proceeding)*
The chief (optionally via a the-architect-style decomposition agent) drafts the issue DAG; the **human applies `phase:graphed`** as the single entry gate (REQ-16), shared with cross-repo requests. The pump never authors graphs. **Building on this.**

## D6 — Drop `auto_graph` from the pilot  *(Proceeding)*
The pilot doesn't need peer-driven auto-graphing; dropping it removes a trust-surface and a code path. Reintroduce only if a peer-driven autonomous-verify workflow proves necessary *after* the answer loop is trusted. **Building on this.**

## D7 — `busy_timeout` on the state.db opener  *(Proceeding)*
`state.db` is WAL (`state.rs:440`) but sets no `busy_timeout`, so a second connection (the read CLI) can hit `SQLITE_BUSY` instead of waiting. The CLI sets its own busy_timeout in step 1; the pump's opener should also get one. Pure correctness, no judgment. **Will land as a one-line pump-opener fix.**

## D8 — void
The embedded server this decision covered was removed.

---

## What I'm building while you're away (decision-free)
1. **Step 1 — read-only `vetinari status/graph/workers/events` CLI** (in progress).
2. **Step 2 — `vetinari` skill** wrapping it (seeding protocol + gate discipline).
