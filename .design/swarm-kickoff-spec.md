# Spec: Swarm kickoff — the two gaps between the VDD executor and a live 5-node federation

> DESIGN/ANALYSIS. Read-only survey of the current tree + the existing crossbridge design (`.design/crossbridge-integration.md` + `-review.md`) + the threat model (`THREAT_MODEL_WORKER_ISOLATION.md`). Grounded in code at `file:line`. No source edited.

## Goal

Get from today's **per-repo executor** (one headless pump driving locally-filed `phase:graphed` issues to `main`) to a **human-supervised 5-node crossbridge federation** where nodes can request work from each other and a human/section-chief can see and steer each node. Name every increment; keep the threat model's trust boundary enforced in the design, not assumed.

## Current state (grounded)

- The orchestrator is a **single-threaded, synchronous, tokio-free** poll loop: `main.rs:136-145` (`tick(); sleep; loop`), one binary only (`orchestrator/Cargo.toml:68`). Root `Cargo.toml` documents the no-async choice as deliberate (cited in the review, B1).
- Pump pickup = **open issue + `phase:graphed` label + no open blockers** (`pump.rs:8-9`, `GRAPHED_LABEL` `pump.rs:156`, pickup scan `pump.rs:463-494` over `list_by_label`/`list_issues`). Unphased issues are ignored.
- **Blockers are the DAG.** `open_blockers` (`crosslink_api/src/repo.rs:178`) is the edge set; a graphed issue with open blockers is held. "Seed a graphed DAG" literally means: create issues, wire blocker edges, apply `phase:graphed`.
- Phase machine: `Graphed → Implementing → QaGate → AdversaryReview → Converged → Landing → Merged | PrOpen`; parked `AwaitingHumanMerge`, `OrchestratorError` (`state.rs:102-123`). `is_drivable = {Graphed, Implementing, QaGate}` (`state.rs:143`). `PhaseSubstate` already exists as a free column (`state.rs:151-174`, schema `state.rs:232`).
- Landing: local FF-guarded bookmark advance (`land_local`, `landing.rs:145`) OR remote push+PR when crosslink's `tracker_remote` is set (`land_remote`, `landing.rs:416-`; `crosslink_api tracker_remote()` `repo.rs:239`). Mode is **global**, not per-issue.
- **The threat model's P0 is CLOSED.** QA now runs inside a hermetic bwrap sandbox — `--unshare-net`, creds/`GH_TOKEN`/pin stripped, grader executed under the worker mount matrix (`qa.rs:11-48`, `SandboxHost::qa_mounts`). This is what moves *trusted-origin* auto-landing to CONDITIONAL-GO. It does **nothing** for intent-level attacks (T2 deferred payload, T4 prompt-injected LLM gate) — those are why *untrusted/inbound* stays HARD NO-GO.
- crosslink_api surface: `read_issue`, `list_by_label`, `open_blockers`, `list_comments`, `tracker_remote`, `comment_write(kind,…)` (kinds validated by crosslink — `repo.rs:286-313`), `label_add`/`label_remove`, `sign`.
- Recovery runs once before the loop: `recover()` (`recovery.rs:338`, called `main.rs:109`).
- AC-24 lint bans `Command::new("jj|git|gh|crosslink|zellij")` via `syn`; exempt crates `xtask`, `zellij_host` (`xtask/src/lint.rs:30,42`). **crossbridge is not on the ban list** and does not need to be — it ships real libraries, so the insulation is a normal crate dep, not a shell-out exception. This confirms `crossbridge-integration.md` REQ-20b.
- **Steering surface today = `just graph` only** (a wrapper over `crosslink issue blocked/ready`, `justfile:120`). Nothing exposes pump phase, substate, workers, or crossbridge state. There is **no `vetinari` CLI** and **no `vetinari` skill** (confirmed: single bin, no skill dir).
- crossbridge is referenced only as *deferred* in the sandbox (`spawn.rs:1060-1061`); the socket root is deliberately **not** mounted into the worker bwrap — which is exactly why crossbridge I/O must be **orchestrator-side, outside any sandbox** (integration doc's role-3 rationale, still correct).

Net: GAP 1 (crossbridge ingestion/answer) is thoroughly *designed* in the two `.design/crossbridge-*` docs and *not built*. GAP 2 (section chief + `vetinari` skill + directive decomposition) is barely designed. This spec builds on GAP 1's existing design (folding in the review's blocking findings, which are correct and still apply) and designs GAP 2 from scratch.

---

## GAP 1 — crossbridge ↔ pump ingestion + auto-answer

The review (`crossbridge-integration-review.md`) already resolved the hard wiring of this gap (B1 dedicated-thread runtime, B2 crosslink-pin coherence, B3 answer state machine, B4 no-auto-land, B5 `phase_substate` authority, N5 second-writer). Those findings are correct and I adopt them wholesale. What follows is the *swarm-kickoff delta*: the trust-boundary enforcement the threat model now demands, and the parts the draft still under-specifies.

### 1.1 The insulation crate `crates/crossbridge_api` (REQ-20b, +review N1)

Surface (owns **all** crossbridge I/O; the only workspace crate allowed to depend on `tokio`, per review N1 — the sync/async membrane is its real job):

```
crossbridge_api::serve(ServeCfg, ShutdownRx) -> ServerHandle   // spawns the dedicated-thread current-thread runtime
crossbridge_api::answer(AnswerReq) -> Result<AnswerOutcome>    // one SubmitAnswer wire round-trip
crossbridge_api::own_slug(RepoRoot, Option<override>) -> Slug  // crossbridge's own derivation (review N7)
crossbridge_api::labels::{XB_INBOUND, XB_SOURCE, XB_REF, ...}   // re-exported marker labels
```

Hard constraints, all from the review, non-negotiable:

- **Dedicated OS thread + `new_current_thread` runtime** (B1). The orchestrator core stays sync. Signals masked on that thread; `run()`'s `process::exit(0)` Ctrl-C path (B1a) must be neutralized — depend on an upstream shutdown channel or reimplement the ~50-line `run` loop on the public `supervisor`/`listeners`/ `handler` modules with a shutdown `mpsc` substituted for `ctrl_c`. Pick reimplement; file the upstream shutdown-channel issue in parallel.
- **`crossbridge_api` public signatures carry vetinari-owned plain types** (issue id `i64`, slug `String`, comment text), **never `crosslink` types** (review N1). `crosslink_api` remains the sole namer of crosslink types.
- **Pin coherence (B2) is the single riskiest wiring and gates everything else.** vetinari pins `crosslink` at `571343b…`; crossbridge git-depends on `crosslink` at `12eb7b9…`. `libsqlite3-sys`'s `links` attribute forces **one** `crosslink` in the graph — two revs is a hard build failure, not a `[patch]` away. Ship `AC-28a` (a `cargo metadata` xtask check that fails the build if >1 `crosslink` source resolves) *before* any embed. State the operating assumption explicitly: **vetinari carries a pinned crossbridge fork** whose `Cargo.toml` crosslink rev is realigned to `571343b…`, bumped as an explicit issue. Do not pretend upstream will stay aligned.

### 1.2 Ingestion + the trust classification (REQ-20d, +threat-model enforcement)

The embedded server creates inbound issues directly in `.crosslink/issues.db` with `xb:inbound`/`xb-source:`/`xb-ref:` and **no `phase:*` label** — so the pump ignores them until graphed (`pump.rs:463-494` strict pickup). This is a **sanctioned second crosslink writer** (review N5): confirm both the server's `Database::open` and `crosslink_api`'s handle use the same journal mode (WAL) + `busy_timeout`, or concurrent writes race `SQLITE_BUSY`. Ship an AC.

**Trust classification — enforced, not assumed.** Inbound = **untrusted origin** (REQ-20f: `peer_slug` is derived from the socket path, not authenticated; any group member, present or future, can submit). The threat model's verdict on untrusted auto-landing is **HARD NO-GO** and P0 alone does not lift it (T2/T4 survive the QA sandbox). Therefore, regardless of `tracker_remote` mode or an `auto_graph` flag:

> **REQ-SWARM-1 (inbound never auto-lands).** An `xb:inbound` issue is driven through implement → QA → adversary → converged and then **stops** at a new parked phase `phase:awaiting-inbound-approval` (mirrors `AwaitingHumanMerge`: not drivable, resumed by a human label `inbound-approved:land` via the REQ-15a resumption machinery). Landing — local FF *or* remote PR — requires that human label. This is the review's Option B, promoted to a hard rule by the threat model. `auto_graph` (if kept) buys autonomous *implementation + verification* for a peer, never a write to `main`. Locally-authored issues are unaffected.

Two consequences to make the trust boundary legible:
- Record the submitting `peer_slug` in the `crossbridge_inbound` event and the issue's first comment (review B4 audit trail; REQ-14 observability triplet).
- The `phase:awaiting-inbound-approval` gate is the human-in-loop checkpoint the threat model requires for *all* untrusted work — it is the single enforcement point, cheap and auditable. Do not spread inbound-trust logic across the pump.

`auto_graph` recommendation for kickoff: **default `false`, and for the pilot leave it `false`** — a human graphs every inbound issue (identical to local issues, one issue-entry policy). Even with the never-auto-land gate, auto-graph hands unauthenticated peers your orchestrator's *compute* and your Anthropic credits; that is fine to enable *after* the pilot proves the answer loop, not on day one.

### 1.3 Auto-answer (REQ-20e/20g, review B3/B5)

Delivery fires when an `xb:inbound` issue reaches **any** terminal phase — `Merged`, `PrOpen`, **and** the failure terminals `AwaitingHumanMerge` / `awaiting-inbound-approval` / `OrchestratorError` — so a peer is never left waiting (review B3). The substep is a `phase_substate` state machine (`state.rs:151`), authority = `state.db`, never the `xb-status:*` label (review B5 — four label values written by three crossbridge binaries, incoherent):

```
answer_pending ──send SubmitAnswer──▶ answer_sent   (then apply xb-status:answered as courtesy; close)
      │
      └─connect fails (source peer offline)──▶ answer_unreachable
                                                    │
                                        retry ≤ 1 / crossbridge_answer_retry_interval_s (new cfg, ~300s)
```

`answer_unreachable` is a **degraded waiting state, not terminal** — retried on poll ticks (not only restart), bounded. Post a `--kind blocker` comment on the inbound issue when unreachable (`comment_write` supports arbitrary validated kinds, `repo.rs:286`). Route the `kind=result` comment/label gathering through `crosslink_api` (review N2); only the `SubmitAnswer` wire round-trip lives in `crossbridge_api`.

### 1.4 Crash-safety / idempotency

- Server start is sequenced **after** the `recover()` scan (`main.rs:109`), not merely after state.db init, so the server can't create an inbound issue mid-scan (review N4).
- Recovery keys off `phase_substate`: an `xb:inbound` issue in `answer_pending` or `answer_unreachable` is re-attempted; `answer_sent` is a no-op (review B3/B5). crossbridge's source-side content-dedup makes a re-send safe → no double-answer.
- Down-time submits are **not buffered**: the peer's `submit` fails fast ("peer not connected") and it retries; no torn write (review N4). State this so no one hunts a phantom buffer.

### 1.5 What makes this a swarm — and what it does NOT

**Swarm substrate:** node A can put *work* on node B's queue (`submit --target B` → `xb:inbound` in B) and get a structured answer back. Cross-node **dependency resolution at issue granularity**, orchestrator-side, crash-safe. That is real and it is what "federation" buys.

**Be honest about the ceiling:**
- **Not worker-initiated.** Role 2 (a sandboxed worker asking a peer mid-task) was rejected — it breaks hermeticity (REQ-8) and needs the socket in the sandbox. So coordination is at the *issue* boundary, between pumps, never inside a running worker.
- **Nothing authors another node's graph.** The pump *executes* DAGs; it does not *generate* them. The decision to `submit` an issue to a peer is made by a human or a section chief, not by the pump. So "autonomously organize as a swarm" overstates it: the honest description is *5 executors + a message bus + human/chief-authored graphs and human/chief-initiated cross-node requests.*
- **No emergent self-organization, no global scheduler, no shared goal decomposition.** Those are not in this design and should not be implied to a stakeholder. The swarm is coordinated *by the humans/chiefs at the seams.*

### 1.6 Worker follow-up work — propose, never author (REQ-SWARM-2)

A worker driving an issue (local or inbound) routinely *discovers* follow-up work: "we also need to parse sub-record Y", "X is blocked on recovering enum Z". That discovery must not be lost — but a worker must **never write the graph**. Workers get crosslink **read-only** (already enforced: the per-role mount matrix binds `<root>/.crosslink/` RO for every role, `spawn.rs:426-459`). Three walls forbid a direct write:

1. **Trust / graph-integrity.** An inbound (untrusted) worker that can create issues + blocker edges can inject arbitrary backlog, build a block-cycle or block-bomb (DoS the DAG), or shape the graph so malicious work is prioritized or auto-landed — the T4 injection surface the threat model keeps on the strictest gate. The graph is the one lever that decides what runs and what lands; an untrusted agent never gets it.
2. **Single-writer invariant (REQ-3).** Pickup is DAG-derived (`open_blockers`, `repo.rs:178`) and recovery assumes the graph is authored out-of-band. A worker writing crosslink is a second writer racing the pump and makes the graph self-modify mid-run — recovery can no longer re-derive deterministically.
3. **Runaway.** Free self-spawned follow-ups let the backlog explode unbounded; the pump would chase an ever-growing self-authored graph no human can keep up with — the opposite of verification-driven.

**The mechanism (propose-don't-commit).** Workers already speak to the orchestrator through crosslink comment *kinds* (`--kind result`/`--kind blocker`). Add **`--kind followup`** (or a structured `proposed_followups` block in the worker's output): title + rationale + suggested blocker edges + a *sketch* of the verifiable gate. It rides the existing worker→orchestrator result channel the pump already reads — **no new write path out of the sandbox.** The orchestrator records these as **proposals** (a `followup:proposed` label / draft), never active graphed issues. **Promotion is the single writer's job, gated:**
- *Trusted-origin (local) node work:* the chief/human promotes, or a chief-preapproved policy auto-promotes within a bounded research area (the human still authored the area and the gate).
- *Untrusted/inbound:* promotion is always human-gated (same posture as `awaiting-inbound-approval`, §1.2).
- *Cross-node* ("need X from repo B") is **not** a worker write either — it becomes a crossbridge `submit` **issued by the orchestrator**, landing in B as an `xb:inbound` that B's human gates.

Net: the graph grows only through the trusted single writer, worker discoveries are first-class (nothing lost), and "chief authors the graph, pump executes it" holds. Build slot: the `followup` kind lands with ingestion (step 4); promotion tooling is a chief/`vetinari`-skill concern (step 2) plus the human gate (step 6).

---

## GAP 2 — section chief + `vetinari` skill + directive decomposition

### 2.1 The section chief is a plain interactive Claude Code — not a vetinari worker

**Argue the pragmatic answer: plain CC, on the host, in the repo dir.** vetinari workers are ephemeral, bwrap-sandboxed, hermetic, fresh-context, headless (no stdin) — every property is the *opposite* of a long-lived, human-facing, stateful advisor. Managing the chief as a worker would (a) break hermeticity, (b) put a human-conversation agent inside a stdin-less sandbox where `--permission-mode default` wedges on every prompt (`roles/mod.rs:44-50`), and (c) give a human's interlocutor the worker mount matrix instead of the repo it needs to read. So the chief runs at the **orchestrator's trust level** (host, unsandboxed), exactly like the human it speaks for.

What it **reads**: `.crosslink/issues.db` (issues, comments, labels, blocker DAG), `state.db` (phase/substate/round/workers — *read-only*), `events.jsonl`, the worktrees under the workspace root, the pump's live panes (`zellij attach vdd-orchestrator`, `main.rs:87-96`).

What it **does** (all through existing write channels, preserving single-writer): seed issues + wire blocker edges + apply `phase:graphed` (via `crosslink issue`), write per-issue `.orchestrator/static_qa.sh`, answer the human, and — because it is host-level, not orchestrator `src/**` — it MAY drive `crossbridge-client submit/answer/peers` directly (AC-24 governs the orchestrator crate, not an interactive agent; same latitude `xtask`/`zellij_host` get).

What it **lacks today:** everything except `just graph`. It cannot see pump phase (that lives in `state.db`, not crosslink), cannot inspect a worker, cannot see crossbridge state. That is the missing interface below.

### 2.2 A read-only `vetinari` query CLI (the surface the skill calls)

New read subcommands, **read-only against `state.db` + `events.jsonl`**, joined with crosslink for the DAG. Read-only is the whole point: writes stay through crosslink so the single-writer invariant (REQ-3) holds and the chief can never corrupt orchestrator state. Ship as subcommands on the existing bin (`orchestrator status …`) or a thin second bin `vetinari`; second bin reads cleaner for the skill and the zellij pane title.

```
vetinari status [--issue N]     # phase, substate, round, empty_round_streak, landing_retry (state.rs row)
vetinari graph                  # DAG: each issue's crosslink blockers × its state.db phase — the real "what's blocked on what"
vetinari workers                # active_workers rows: role, round, workspace, pid, last_heartbeat
vetinari events [--issue N] [--tail]   # events.jsonl slice (spawn/transition/qa_result/…)
vetinari crossbridge            # inbound issues, answer substate, xb-source peer, degraded flag
```

Load-bearing constraint: the **running orchestrator holds `state.db` open.** The CLI must open a **second read-only connection** under the same WAL + busy-timeout discipline (same concern as review N5). Flag: if `state.db` is not WAL, a reader can block the pump — verify the journal mode before shipping this.

`vetinari graph` is the one genuinely new synthesis: today `just graph` shows crosslink `ready`/`blocked` (dependency edges) but is **blind to execution phase**. Joining `open_blockers` (`repo.rs:178`) with the `state.db` phase gives the chief the first real "swarm status" view of its node.

### 2.3 The `vetinari` skill

A `SKILL.md` (none exists) that documents, for the section chief:
1. **Introspect** — the `vetinari status/graph/workers/events/crossbridge` commands above, with worked examples.
2. **Steer** — the *seeding protocol*: how to file a graphed issue DAG (`crosslink issue new`; wire blockers; author `.orchestrator/static_qa.sh`; apply `phase:graphed` last so the pump doesn't pick up a half-seeded issue), how to reprioritize (add/remove blockers), how to park (remove `phase:graphed`).
3. **Federate** — `crossbridge-client peers/submit/answer` for cross-node work requests, and how to read inbound issues (`vetinari crossbridge`).
4. **The gate discipline** — 2.4 below: every graphed issue MUST carry a deterministic `static_qa.sh`, and what that means for RE.

The skill is *documentation + a thin CLI*, not new orchestrator behavior — it is the cheapest high-leverage increment and should ship first.

### 2.4 Directive → graphed-issue decomposition — the hardest conceptual gap

"Seed with research directives and autonomously organize" collides with a hard fact: **vetinari executes graphs; it does not author them, and it cannot verify a task that has no deterministic gate.** `phase:graphed` pickup requires a committed `.orchestrator/static_qa.sh` that returns pass/fail (`qa.rs`), because convergence and landing are gated on it. "Reverse-engineer subsystem X" has no natural pass/fail.

**Who authors the graph:** the human or the **section chief** (optionally invoking a the-architect-style decomposition agent — the same "design before building" discipline this very file embodies). Not the pump. Recommendation for kickoff: chief drafts the DAG, **human applies `phase:graphed`** (keeps the REQ-16 human-gate; one issue-entry policy shared with inbound).

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
3. **Resolve crossbridge pin coherence + `crossbridge_api` skeleton** (1.1, B2). Pinned crossbridge fork realigned to vetinari's crosslink rev; `serve`/`answer` compile; tokio quarantined. *Verify:* `AC-28a` (single-crosslink `cargo metadata` check) green; `AC-28` (disabled-by-default, fixture dogfood still passes, no socket opened). *Highest-risk wiring — isolate it here.*
4. **Embedded server (dedicated thread, B1) + inbound ingestion unphased** (1.2). *Verify:* `AC-29` registration, `AC-30` a peer `submit` lands an `xb:inbound` issue that the pump does **not** pick up; SIGINT still clean-shuts the orchestrator (server thread can't `process::exit`).
5. **Answer-back state machine** (1.3, B3/B5). Substates + terminal-and-failure delivery + `answer_unreachable` bounded retry. *Verify:* `AC-32` answer round-trip, `AC-33` crash mid-`answer_pending` re-sends once (recovery off `phase_substate`).
6. **Inbound human-gate enforcement** (`phase:awaiting-inbound-approval`, REQ-SWARM-1). Inbound never auto-lands regardless of mode. *Verify:* new AC — a graphed inbound issue converges and parks; only `inbound-approved:land` advances it; the peer's answer reports the pending-approval state.
7. **(unsupervised only, out of pilot scope) P1 containment** — egress filter (`spawn.rs:1080`), scoped ephemeral creds (`spawn.rs:1069`), per-worker object store (`spawn.rs:445`). Prerequisite to *any* unsupervised operation; see checklist.

Steps 1–2 and 3 are parallelizable (disjoint surfaces: read CLI vs. pin/crate). 4→5→6 are strictly sequential.

---

## Pre-kickoff checklist

### Needed for a **supervised pilot** (human watches; human approves every land)

- [x] **P0 QA sandbox** — done (`qa.rs:11-48`); the reason trusted-origin is CONDITIONAL-GO.
- [ ] Build steps **1–6** above (read CLI, skill, crossbridge_api, embedded server, answer loop, inbound human-gate).
- [ ] `AC-28a` pin-coherence check green; **decision recorded** that vetinari carries a pinned crossbridge fork (B2).
- [ ] `state.db` confirmed **WAL + busy_timeout** so the read CLI and the second crossbridge writer never block the pump (review N5, §2.2).
- [ ] Host-wide `crossbridge-supervisor.service` running (singleton; the orchestrator must **not** start it — REQ-20c).
- [ ] Per-node `.orchestrator/config.toml`: `[crossbridge] enabled=true, group="reversing", slug=<node>, auto_graph=false`.
- [ ] zellij 5-tab / 2-pane layout script (host-side; a plain zellij layout, not orchestrator code — no AC-24 concern).
- [ ] **At least one worked directive→gate-able-issue decomposition** for the target subsystem (§2.4) — proof the hardest gap is surmountable *for this RE target*, not just in theory. If no proxy gate can be written, the target is not swarm-drivable and the pilot scope must shrink to the part that is.
- [ ] Human-in-loop confirmed on **every** land (local FF and inbound approval).

### Additionally needed for **unsupervised** operation

Per the threat model, unsupervised applies **only to locally-authored (trusted-origin) issues within a node.** *Unsupervised inbound auto-land stays out of scope* — the threat model calls it HARD NO-GO and warrants a human checkpoint even after all mitigations. So REQ-SWARM-1's `phase:awaiting-inbound-approval` gate remains even in the "unsupervised" federation.

- [ ] **P1 egress filtering** — worker reaches only the Anthropic API (`spawn.rs:1080`, closes T5 exfil path).
- [ ] **P1 scoped ephemeral creds** — not the operator's config-dir RO overlay (`spawn.rs:1069`, T5).
- [ ] **P1 per-worker object store** — no shared `.jj/`+`.git/` RW mount (`spawn.rs:445`, closes T3 corruption / de-worms the federation).
- [ ] **P2 second content gate or per-peer auth** — the LLM adversary is not a sufficient sole gate against T4 injection for anything untrusted.
- [ ] A **track record of supervised runs** before flipping the human out of the trusted-origin land loop.

---

## Threat-model reconciliation

| Recommendation | Trust boundary it respects |
|---|---|
| REQ-SWARM-1: inbound parks at `awaiting-inbound-approval`, never auto-lands | Untrusted origin ⇒ HARD NO-GO on auto-land holds even post-P0; single enforced human checkpoint |
| `auto_graph=false` for pilot; even `true` never lands | Peer gets compute, never `main`-write; makes REQ-20f's trust statement honest |
| Record `peer_slug` in event + first comment | Audit trail for untrusted submitter (REQ-14 triplet) |
| Section chief = host-level plain CC, not a worker | Chief runs at orchestrator trust level, same as the human; no untrusted agent gets host latitude |
| `vetinari` CLI is **read-only**; writes stay via crosslink | Preserves single-writer (REQ-3); chief cannot corrupt orchestrator state |
| crossbridge I/O is orchestrator-side, outside bwrap | Socket never enters the sandbox (`spawn.rs:1060`); no new escape vector |
| Answer fires on failure terminals too | Peer never hangs; no silent drop of untrusted work |
| Unsupervised gated on P1(egress/creds/store)+P2 | Directly the threat model's §4/§5 prerequisites; unsupervised *inbound* stays out of scope regardless |

Trusted-origin (locally-authored) issues: CONDITIONAL-GO post-P0, unchanged by this spec. Untrusted-origin (inbound) issues: this spec's job is to make the HARD-NO-GO boundary a *structural* property (the approval-park phase), not a policy note.

## Open questions

- **Upstream crossbridge shutdown channel (B1a):** file it now and depend on it, or ship the ~50-line `run` reimplementation in `crossbridge_api` for the pilot? Reimplement is faster to a pilot; the upstream fix is the clean long-term. Pick reimplement + file upstream in parallel.
- **`vetinari` as a subcommand of `orchestrator` vs. a second bin?** Second bin is cleaner for the skill/pane-title; subcommand is less packaging. Lean second bin.
- **Is `state.db` currently WAL?** If not, the read CLI (§2.2) and the second crossbridge writer (N5) both need it before kickoff — verify early.
- **Directive decomposition ownership (§2.4):** chief-only, or a dedicated decomposition agent? Either works; the *human `phase:graphed` gate* is the invariant. What is the concrete first RE target, and can a proxy gate be written for it? — this is the go/no-go for the whole pilot, and it is a domain question, not an engineering one.
- **Does the pilot even need `auto_graph`?** Recommendation: drop it from the pilot entirely (Option A simplicity); reintroduce only if a peer-driven autonomous-verify workflow proves necessary *after* the answer loop is trusted.
