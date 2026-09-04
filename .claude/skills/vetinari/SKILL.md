---
name: vetinari
description: Use when acting as a repo's section chief — introspecting a vetinari node (phase / DAG / workers / crossbridge) and steering it by seeding a graphed issue DAG, reprioritizing, parking, and driving cross-node requests. Reads via the read-only `vetinari` CLI; writes only via `crosslink` (single-writer discipline).
---

# vetinari — introspect and steer your node

You are the **section chief**: a plain interactive Claude Code running on the host, in the repo directory, at the orchestrator's trust level — not a sandboxed vetinari worker.
Your node runs a headless pump that drives every open, `phase:graphed` issue with no open blockers through implement → QA → adversary → converged → land.
Your job is to see what the node is doing and to author the graph it executes.

**The one rule that keeps the node correct: reads go through `vetinari`, writes go through `crosslink`.**
The `vetinari` CLI is *read-only by construction* — it opens `state.db` `SQLITE_OPEN_READ_ONLY` and never touches crosslink labels. It is physically incapable of corrupting orchestrator state, and that is the point.
Every mutation to the graph — create, block, label, comment — is a `crosslink` command. The pump is the single writer of `state.db`; crosslink is the single writer of the issue graph; you write the graph only through `crosslink`. Never try to make `vetinari` write anything; it can't, and reaching for a write there is the sign you should be typing `crosslink`.

Run every command from inside the repo (or pass `--orchestrator-dir PATH`); the node lives at `.orchestrator/` beside `.crosslink/`.

---

## 1. Introspect — the five read commands

All five take `--json` (machine output) and `--orchestrator-dir PATH` (override discovery, which otherwise walks up from cwd). Nothing here writes.

### `vetinari status [--issue N]`
The persisted phase machine — phase, substate, round, empty-round streak, landing-retry count, convergence mode — for one issue or all tracked issues.
Reach for it to answer "where is issue N in its lifecycle?" and "is anything stuck retrying to land?".

```
$ vetinari status
ISSUE  PHASE            SUBSTATE        ROUND  EMPTY_STREAK  LANDING_RETRY  CONVERGENCE
#41    merged           -               3      2             0              adversary-quiet
#42    qa-gate          -               1      0             0              adversary-quiet
#43    landing          rebase-started  2      1             1              adversary-quiet
```

Phase tokens (from `state.db`): `graphed`, `implementing`, `qa-gate`, `adversary-review`, `converged`, `landing`, `merged`, `pr-open`, and the parked terminals `awaiting-human-merge` and `orchestrator-error`.
`graphed`/`implementing`/`qa-gate` are *drivable*; `merged`/`pr-open` are success terminals; `awaiting-human-merge`/`orchestrator-error` need a human.
`--issue N` on an issue the pump never picked up prints "not tracked" — a graphed issue held by an open blocker has no `state.db` row yet (see `graph`).

### `vetinari graph`
**The only view that joins the dependency DAG with execution phase — the node's real "what is blocked on what".**
`just graph` (crosslink `ready`/`blocked`) shows the edges but is blind to phase; this joins each issue's crosslink **open blockers** with each issue's `state.db` phase.
This is your primary steering instrument: it tells you what the pump will pick up next (anything `ready`) and where every blocker sits.

```
$ vetinari graph
ISSUE  PHASE       BLOCKED_BY
#41    merged      ready
#42    qa-gate     ready
#43    untracked   #42(qa-gate)
#44    untracked   #42(qa-gate), #43(untracked)
```

`ready` = no open blockers → pump-eligible the moment it also carries `phase:graphed`.
`untracked` phase = graphed but not yet ingested into `state.db` (still held by a blocker). A blocker shown as `#42(qa-gate)` is itself in flight; `#43(untracked)` is graphed-but-waiting.
The id set is the union of every `state.db`-tracked issue and every open `phase:graphed` issue, so a fully-blocked graphed issue still shows up.

### `vetinari workers`
Live workers from `active_workers`: short uuid, issue, role, round, pid, heartbeat age (flagged `STALE` past ~120s), workspace path.
Reach for it to see what is running right now and whether a worker has gone silent.

```
$ vetinari workers
WORKER    ISSUE  ROLE         ROUND  PID    HEARTBEAT  WORKSPACE
a1b2c3d4  #42    implementer  1      31820  6s         /…/.vdd-workspaces/issue-42-impl
e5f6a7b8  #43    adversary    2      31955  148s STALE  /…/.vdd-workspaces/issue-43-adv
```

`STALE` is advisory — this read-only view reports the missing heartbeat; the pump's own watchdog is what acts on it.

### `vetinari events [--issue N] [--tail K]`
The trailing slice of the event stream (spawn / transition / qa_result / …), oldest-first, `K` defaults to 20.
`--issue N` filters to one issue's history; use it to reconstruct "what happened to #43?" after the fact.

```
$ vetinari events --issue 43 --tail 4
TS          KIND         ISSUE  WORKER    PAYLOAD
1712.. spawn        #43    e5f6a7b8  {"role":"adversary","round":2}
1712.. qa_result    #43    e5f6a7b8  {"verdict":"pass"}
1712.. transition   #43    -         {"from":"qa-gate","to":"landing"}
1712.. land_retry   #43    -         {"attempt":1,"reason":"non-ff"}
```

### `vetinari crossbridge`
Inbound/outbound crossbridge issues by their `xb:*` marker labels, with source peer, courtesy status label, ref, and answer substate.
Reach for it to see what peers have asked of your node and how far each inbound request has progressed.

```
$ vetinari crossbridge
crossbridge integration not yet active (swarm-kickoff spec §1, not built).
Showing crosslink issues carrying xb:* marker labels only.

INBOUND:
ISSUE  TITLE                       SOURCE     XB_STATUS  XB_REF  SUBSTATE
#57    Parse the FOO record type   node-beta  -          req-88  -

OUTBOUND: none
```

The "integration not yet active" note is honest: the embedded server, the answer state machine, and the `awaiting-inbound-approval` gate land in a later step. Until then this view reflects only labels already present. The answer substate columns fill in when that step ships.

---

## 2. Steer — the seeding protocol

You author the graph the pump executes. The pump picks up an issue iff it is **open ∧ `phase:graphed` ∧ has no open blockers**. Everything below encodes a DAG into exactly that condition.

**Apply `phase:graphed` LAST, always.** The pump scans continuously; the instant an issue is `phase:graphed` and unblocked it is eligible. If you label before wiring blockers or before committing the gate, the pump can grab a half-seeded issue with no gate and no dependencies. Seed the whole issue, *then* graph it.

### Seed one issue

```bash
# 1. Create it (capture the id; -q prints just the number).
id=$(crosslink -q issue create "Parse format X, round-trip N committed samples" -p high)

# 2. Wire its blocker edges — the DAG. "issue <id> blocked by <blocker>".
crosslink issue block "$id" 42        # this issue waits on #42
crosslink issue block "$id" 43        # …and on #43

# 3. Author its verifiable gate (see §4). This is the load-bearing artifact —
#    without a deterministic static_qa.sh the issue is not vetinari-drivable.
#    Commit it in the issue's workspace at .orchestrator/static_qa.sh.
#    (write the file, then commit it on the issue's base — see §4)

# 4. LAST: mark it graphed so the pump may pick it up.
crosslink issue label "$id" phase:graphed
```

For a wider DAG, create every issue and wire every edge first, and label them all `phase:graphed` only after the whole graph and every gate are in place. A leaf (no blockers) becomes pump-eligible immediately on labeling; an interior node waits until its blockers close.

### Reprioritize
The DAG *is* the schedule — reorder by editing edges, not by touching `state.db`.

```bash
crosslink issue block   "$id" 50    # add a dependency: hold $id until #50 closes
crosslink issue unblock "$id" 43    # drop a dependency: let $id run sooner
```

### Park / unpark
Remove `phase:graphed` to take an issue back out of pump scope without deleting it or its edges.

```bash
crosslink issue unlabel "$id" phase:graphed   # park — pump stops considering it
crosslink issue label   "$id" phase:graphed   # unpark — back in scope (gate must still be committed)
```

### Leave an audit trail
Typed comments are the narrative record the pump and later chiefs read. Every comment needs a `--kind`.

```bash
crosslink issue comment "$id" "Gate: parser round-trips 12 committed .foo fixtures byte-for-byte" --kind decision
```

Reads that inform steering — `crosslink issue ready`, `crosslink issue blocked`, `crosslink issue list -l phase:graphed`, `crosslink issue show <id>` — are fine from `crosslink` too; prefer `vetinari graph` for the phase-joined view.

---

## 3. Federate — cross-node requests

Cross-node coordination happens at the **issue boundary**, between pumps, driven by you — never from inside a running worker. Because you are host-level, you MAY drive `crossbridge-client` directly (unlike the sandboxed orchestrator).

```bash
crossbridge-client peers                              # slugs of currently-registered peer repos, one per line
crossbridge-client submit --issue 42 --target node-beta   # put local issue #42 onto node-beta's queue as an xb:inbound issue
crossbridge-client answer --issue 57                 # send inbound issue #57's result comments back to its source repo
```

`--slug <SLUG>` overrides your own repo's slug (needed in a worktree or a clone with no `origin` remote).

**Reading inbound work** that peers have put on *your* queue:

```bash
vetinari crossbridge                        # phase-joined view (preferred)
crosslink issue list -l xb:inbound          # raw list of inbound issues
```

**Inbound is untrusted, and it is your job to gate it (REQ-SWARM-1).**
An inbound issue's source peer is derived from a socket path, not authenticated — treat it as untrusted origin.
Inbound issues arrive **unphased**: the pump ignores them until a human graphs them, exactly like a local issue. You graph an inbound issue with the same seeding protocol (§2), and only after you have read it and written it a real gate.
Inbound work **never auto-lands** — even fully converged it parks for an explicit human land approval. Do not try to shortcut that; the human checkpoint on untrusted work is the whole safety boundary.

---

## 4. Gate discipline — every graphed issue MUST carry a deterministic gate

This is the hard, load-bearing part. **vetinari executes graphs; it cannot verify a task that has no deterministic gate.**

Every graphed issue must commit an executable `.orchestrator/static_qa.sh` in its workspace that returns **pass/fail via exit code (0 = pass)**. The pump runs it in a hermetic sandbox at the QA gate; **convergence and landing are gated on it**. No gate → the issue is not drivable, and worse, a mis-labeled gate-less issue is exactly what the "label graphed LAST" rule exists to prevent.

The gate tests a **proxy artifact with a checkable invariant** — never "comprehension". Concrete RE patterns that work:

- **Parser round-trip.** *"Write a parser for format X that round-trips these N captured samples byte-for-byte."*
  → `static_qa.sh` runs the parser over committed fixtures and asserts byte-exact round-trip.
- **Struct-layout header.** *"Recover the layout of struct S: emit a C header whose `sizeof`/`offsetof` match these ground-truth probe values."*
  → the gate compiles the header and asserts every `sizeof`/`offsetof` constant equals its probe value.
- **Coverage target.** *"Reach basic-block coverage ≥ C on target T under harness H."*
  → the gate runs the harness and asserts measured coverage ≥ C.

```bash
#!/usr/bin/env bash
# .orchestrator/static_qa.sh — deterministic pass/fail. exit 0 = pass.
set -euo pipefail
cargo build --quiet
for sample in fixtures/*.foo; do
    ./target/debug/fooparse "$sample" > /tmp/rt.foo
    cmp -s "$sample" /tmp/rt.foo || { echo "round-trip mismatch: $sample"; exit 1; }
done
echo "all fixtures round-trip byte-for-byte"
```

The gate is self-bounded (~10 min wall-clock) and its last ~50 lines of output feed the next worker on failure — write clear failure messages.

**What is NOT a vetinari issue.**
Open-ended "understand this blob", "figure out what this subsystem does", "explore format X" — anything whose only output is a report — has no deterministic gate. Vetinari cannot verify a report. That work is **yours or the human's**: do the exploration, then reduce a *piece* of it to a proxy gate and graph *that*.

**Defining the gate is the research judgment, and it cannot be automated.**
Choosing "round-trip these 12 samples" as the proxy for "understand this format" *is* the reversing insight. The node autonomously drives exactly the fraction of RE you have already reduced to a deterministic assertion — no more. State that ceiling plainly; do not graph an issue whose gate you cannot write.
