# Architect review: crossbridge-integration.md (REQ-20 / AC-28 series)

> Pre-implementation design review of the DRAFT `crossbridge-integration.md`.
> Reviews the proposed REQ-20 series and AC-28 series against the canonical
> `vdd-orchestrator.md` invariants. Findings are numbered; each carries a
> severity and a concrete recommended change. Blocking findings (B) must be
> resolved before the draft folds into the canonical spec; nice-to-haves (N)
> may be deferred but should be acknowledged.

## Verdict

The role-3 scoping decision is sound and the rejection of roles 1 and 2 is
well-argued — role 2 genuinely would break REQ-6/7/8 and that is correctly
called out. The draft is, however, **not ready to fold in**. Three blocking
findings (B1 runtime model, B2 crosslink-pin unification, B3 answer
reachability) each invalidate a load-bearing claim in the draft. The trust
posture (B4) is also blocking as written because `auto_graph` as specified
contradicts the design's own crash-safety and human-gate posture without
acknowledging it. Everything else is refinement.

---

## B1 — Embedding a tokio server contradicts the deliberately sync orchestrator (BLOCKING)

**Severity: blocking.** Open Question 5 asks "does the orchestrator already
have a tokio runtime, or is it currently sync?" The answer is unambiguous and
the draft must stop hedging: **the orchestrator is deliberately, by design,
not async.** `crates/orchestrator/Cargo.toml` has no tokio dependency. The
root `Cargo.toml` documents the choice twice in prose: `jj_api` "presents a
synchronous surface ... driving futures to completion ... — no tokio runtime
is pulled into the binary" and `rusqlite`'s "synchronous API matches the
single-threaded tick loop — no async runtime is pulled in." The whole
orchestrator is a single-threaded poll loop (`pump.rs`: poll -> pick ->
dispatch). REQ-20c's phrase "a supervised background task on its tokio
runtime" describes a runtime that does not exist and that the design has
explicitly refused.

`crossbridge-server::run` is `async fn` and hard-depends on tokio with
features `rt, net, io-util, macros, signal, time, sync`. It also installs its
own `signal::ctrl_c()` handler and — worse — `serve_one_session` calls
`std::process::exit(0)` directly on Ctrl-C (see `run.rs:119`). Embedding that
task in-process means crossbridge's signal handling races the orchestrator's
own signal handling (`main.rs` is responsible for graceful shutdown and
crash-safe state per REQ-15), and a SIGINT delivered to the orchestrator can
be consumed by crossbridge's handler which then calls `process::exit(0)` —
bypassing every flush/checkpoint the orchestrator needs to do before dying.
That is a direct regression of REQ-15 crash-safety.

**Recommended change.** Rewrite REQ-20c to mandate the dedicated-thread
option that Open Question 5 lists as the alternative, and make it normative,
not a "weigh against":

> REQ-20c (revised). The embedded crossbridge server runs on a **dedicated
> OS thread** that owns its **own current-thread tokio runtime**
> (`tokio::runtime::Builder::new_current_thread`), spawned by `main.rs` after
> state.db init and the Z1 zellij bootstrap. The orchestrator core remains
> synchronous and tokio-free; tokio is a dependency of `crossbridge_api`
> only, never surfaced in the orchestrator's own `src/**`. The server thread
> communicates with the sync tick loop exclusively through a `std::sync::mpsc`
> channel and the shared `state.db` (SQLite, accessed under the existing
> connection discipline — see B6). The orchestrator MUST install its own
> signal handler before spawning the server thread and MUST NOT allow
> crossbridge's `ctrl_c` path to drive process exit; because `run.rs` calls
> `std::process::exit(0)` on Ctrl-C, the server thread MUST be given a
> runtime on which `ctrl_c` never fires — i.e. signals are masked on that
> thread (or the server is driven via a private fork of `run()` that takes a
> shutdown channel instead of `signal::ctrl_c()`; see B1a).

**B1a (sub-finding, blocking).** `crossbridge-server::run` provides no clean
programmatic shutdown — its only non-error exit is `ctrl_c`, and
`serve_one_session` calls `process::exit(0)` outright. There is no
`CancellationToken` or shutdown-channel parameter. `crossbridge_api::serve`
therefore cannot honor "supervised background task" semantics: the
orchestrator cannot ask it to stop, and on orchestrator shutdown the server
thread either leaks or force-exits the process. The draft's REQ-20c phrase
"supervised background task" is not currently implementable against the
upstream API. Either (a) file an upstream issue to add a shutdown channel to
`run()` and depend on that — preferred, mirrors the REQ-3a discipline of
only consuming a stable surface — or (b) `crossbridge_api` reimplements the
`run` loop (it is ~50 lines) on top of the public `supervisor`, `listeners`,
`handler` modules with a shutdown channel substituted for `ctrl_c`. Option
(b) is more code than REQ-20b's "wraps `run()`" claim admits — REQ-20b must
be corrected to say so. The draft must pick one and say which.

---

## B2 — The crosslink-pin unification is currently a hard version conflict, not a `[patch]` away (BLOCKING)

**Severity: blocking.** This is Open Question 3, and it is the riskiest
wiring exactly as the draft fears. The two pins **do not currently
reconcile**:

- vetinari's `npins/sources.json` pins `crosslink` at
  `571343ba8e0ef5b26b943612f635c42cc8953c8f`.
- crossbridge's workspace `Cargo.toml` git-depends on `crosslink` at
  `rev = "12eb7b917e9ef726f40eb2f9b36cf87fa38efa4d"`.

These are different revisions. The draft's REQ-20b says the generated
`.cargo/config.toml` MUST `[patch]` crossbridge's crosslink git dependency to
vetinari's single crosslink source path. A `[patch]` *can* redirect a git
dependency to a path — but cargo still requires the patched crate's version
to satisfy crossbridge's version requirement, and more importantly, **the
crossbridge code must still compile against whatever crosslink API is at
vetinari's pinned revision.** `crossbridge-server/handler.rs` calls a wide
crosslink surface: `Database::open`, `create_issue`, `add_label`,
`add_comment`, `transaction`, `get_comments`, `get_labels`, `remove_label`,
`get_issue`, `close_issue`, `list_issues`. If `571343b` changed any of those
signatures relative to `12eb7b9`, the `[patch]` makes crossbridge fail to
compile — and the failure is in *crossbridge's* source, not vetinari's, so it
is not localized to an insulation crate. REQ-3a's whole promise ("when
crosslink refactors break the build, the fix is localized to `crosslink_api`")
does not hold for crossbridge's own crosslink calls.

The draft acknowledges "the npins crosslink and crossbridge pins must be
chosen so their crosslink revisions reconcile" but treats that as a wiring
detail. It is the central constraint and it has a real cost: **vetinari can
no longer bump its crosslink pin independently.** Any crosslink bump must be
a coordinated bump of crossbridge too (so crossbridge's git rev matches), or
crossbridge must be carried on a vetinari-controlled fork.

**Recommended change.** Rewrite REQ-20b's "Crosslink-pin unification"
paragraph to state the constraint honestly and pick a mechanism:

> The orchestrator embeds `crossbridge-server`, which git-depends on
> `crosslink` at a revision chosen by crossbridge's upstream. vetinari also
> depends on `crosslink` (via `crosslink_api`, REQ-3a). Cargo's `links`
> attribute on `libsqlite3-sys` (already documented in
> `orchestrator/Cargo.toml`) forces the *entire* dependency graph to one
> `crosslink` instance — two revisions is not merely "two incompatible
> types", it is a hard `cargo` build failure. Therefore:
> (1) The npins `crosslink` pin and the crosslink revision crossbridge
>     git-depends on MUST be the *same commit*. This is a release-coupling
>     constraint, not a `[patch]` convenience: bumping crosslink is now a
>     three-way coordinated change (crosslink, crossbridge, vetinari) tracked
>     as a single issue, and the issue MUST verify crossbridge compiles
>     against the new crosslink before the vetinari pin moves.
> (2) The generated `.cargo/config.toml` MUST `[patch]` crossbridge's
>     `crosslink` git dependency to vetinari's single nix-provided crosslink
>     source path, so only one copy is built.
> (3) If upstream crossbridge's pinned crosslink revision cannot be matched
>     to vetinari's required revision, vetinari MUST consume crossbridge from
>     a pinned fork whose `Cargo.toml` crosslink rev is realigned — and that
>     fork is itself an npins source whose bump is an explicit issue. The
>     draft MUST state which of "upstream stays aligned" vs "vetinari forks
>     crossbridge" is the operating assumption.

Add an acceptance criterion:

> AC-28a (pin coherence). A build-time check (xtask or a `cargo metadata`
> assertion) fails the build if more than one `crosslink` source resolves in
> the dependency graph, or if the resolved `crosslink` source path is not the
> single nix-provided one. This catches a crossbridge pin bump that silently
> reintroduces a second crosslink.

---

## B3 — The answer step can be permanently un-sendable; recovery as specified loops forever (BLOCKING)

**Severity: blocking.** REQ-20e/20g treat "send the answer" as an operation
that only needs idempotency. It is also an operation that can **never
succeed**, and the recovery design has no terminal state for that case.

Tracing the client `answer` path (`crossbridge-client/src/main.rs:134-196`):
the answer is sent by connecting *as a client* to
`socket_root()/<own-slug>/<source-slug>.socket`. Per `paths.rs:78`, that
socket file (`<root>/<peer>/<own>.socket` from the source's point of view) is
created by **the source repo's own server** when it has vetinari in its peer
set, and is unlinked the moment the source's server loses the supervisor
session or the source peer leaves (`listeners.rs:109-122`, `clear()` on
disconnect). Consequences the draft does not address:

1. **The source repo's server must be online at answer time.** If the source
   repo that submitted the issue has since shut down its crossbridge server,
   `UnixStream::connect` fails with `ENOENT`/`ECONNREFUSED`. The answer
   cannot be sent. This is one of the edge cases the prompt explicitly asks
   about and the draft does not mention it at all.
2. **REQ-20g's recovery rule is "no `xb-status:answered` label => re-send".**
   Combined with (1), an inbound issue whose source has permanently
   disappeared will be retried on *every* orchestrator restart, forever,
   with no backoff and no terminal state. That is a REQ-15 violation:
   recovery is supposed to be deterministic and converge.
3. **An inbound issue that fails QA forever never reaches a terminal phase**
   (it bounces `qa-gate -> implementing` indefinitely, REQ-9), so the answer
   step never fires and the source repo waits forever with no signal. The
   prompt asks about this; the draft is silent.

**Recommended change.** REQ-20e and REQ-20g need a real state machine, not a
single `answer_pending -> answer_sent` pair:

> REQ-20e (revised). The answer substep has substates `answer_pending`,
> `answer_sent`, and `answer_unreachable`. Sending an answer is a *bounded*
> retry: on connect failure (source peer socket absent) the orchestrator
> records `answer_unreachable`, emits a `crossbridge_answer` event with
> `outcome=unreachable`, posts a `--kind blocker` comment on the inbound
> issue ("answer could not be delivered to <source>; peer offline"), and
> **leaves the issue in `answer_unreachable`**. On each subsequent poll tick
> (not just on restart) the orchestrator retries an `answer_unreachable`
> issue at most once per `crossbridge_answer_retry_interval_s` (new config,
> default e.g. 300s). Reaching `answer_sent` applies `xb-status:answered`
> and closes the issue. `answer_unreachable` is NOT terminal — it is a
> degraded waiting state — but recovery treats it identically to
> `answer_pending` (re-attempt, deduped source-side) so there is no special
> recovery row.

> REQ-20g (revised). Recovery keys off `phase_substate`, not the
> `xb-status:answered` label (see B5 — the label set is unreliable). An
> `xb:inbound` issue persisted in `answer_pending` or `answer_unreachable` is
> re-attempted. An issue already in `answer_sent` is a no-op. Crossbridge's
> content-dedup on the source side makes a re-attempt safe even if the prior
> attempt partially succeeded.

For the never-converges case, add to REQ-20 (or a new REQ-20h):

> An `xb:inbound` issue that the orchestrator drives to `phase:awaiting-
> human-merge` or `phase:orchestrator-error` (i.e. a non-success terminal or
> poison state) MUST still answer the source — with a `kind=result` comment
> describing the failure — so the submitting peer is never left waiting
> indefinitely. The answer substep therefore fires on *every* terminal
> phase, success or failure, not only on `phase:merged` / `phase:pr-open`.

This last point also resolves an asymmetry: REQ-20e currently makes a peer's
issue silently vanish if it fails QA, which is a worse experience than a
failed answer.

---

## B4 — `auto_graph` as specified contradicts the design's own human-gate and crash-safety posture (BLOCKING)

**Severity: blocking** (as a spec-coherence defect, not necessarily a "drop
it" verdict). This is Open Questions 1 and 2.

`auto_graph = true` means: an unauthenticated peer (REQ-20f is explicit —
`peer_slug` is derived from the socket path, not cryptographically verified,
and there is no per-peer allowlist) can cause vetinari to autonomously
implement arbitrary code and **land it on `main`** with no human in the loop.
In local mode (REQ-17, `tracker_remote` empty) landing is a `jj rebase` +
fast-forward of the `main` bookmark — there is no PR, no review gate, nothing.

The draft's REQ-20f hand-waves this as "trusting them ... to trigger
autonomous code changes that land without human review" and calls
`auto_graph = false` the "safe default." But a config flag whose `true`
setting hands `main`-write to an unauthenticated network of peers is not a
defensible feature to ship in the MVP of a system whose entire spec is built
around determinism and human-filed issues (REQ-16: "Issues are filed and
decomposed by humans"). The Implementer worker is sandboxed (REQ-4) but the
sandbox constrains *tool surface*, not *intent* — a malicious or
typo-ridden inbound issue ("delete the auth check and add a passing test")
sails straight through `static_qa.sh` if QA passes.

Open Question 1's third option — force inbound issues to land via PR
regardless of `tracker_remote` — is the right instinct but does not go far
enough: in a pure-local repo there may be no remote to open a PR against at
all, so "force PR" is not always available.

**Recommended change.** Two acceptable resolutions; the draft must pick one
and the spec must stop describing `auto_graph -> auto-land` as merely a
trust toggle:

> Option A (preferred for MVP — drop auto-land entirely).
> Remove `auto_graph` from REQ-20a/20d/20f and AC-31. Inbound issues are
> ALWAYS ingested unphased; a human applies `phase:graphed` after review,
> identical to local issues (REQ-16, Q1). This keeps exactly one issue-entry
> policy in the whole system and removes an unauthenticated path to autonomy.
> "Autonomous inbound" can be filed as a later issue once crossbridge grows
> per-peer authentication.

> Option B (keep auto-graph, but never auto-land).
> Retain `auto_graph` but redefine it: an auto-graphed `xb:inbound` issue is
> driven through implement -> QA -> (adversary) -> converged and then STOPS
> at a new phase `phase:awaiting-inbound-approval`. Landing requires a human
> label (`inbound-approved:land`), reusing the REQ-15a human-label
> resumption machinery. The peer gets autonomous *implementation and
> verification* but a human still gates the merge. This makes the trust
> statement in REQ-20f honest ("trusting them to consume orchestrator
> compute", not "to write your main branch"). REQ-20e's answer-back then
> reports either the landed result or the pending-approval state.

Either way, REQ-20f's sentence "enabling `crossbridge.auto_graph`
additionally means trusting them to trigger autonomous code changes that
land without human review" must be deleted or rewritten — under Option A it
is moot, under Option B it is false.

Independently of A/B: REQ-20f should add that the orchestrator MUST record
the submitting `peer_slug` (from `xb-source:`) in the `events.jsonl`
`crossbridge_inbound` event and in the issue's first comment, so there is an
audit trail of who submitted what. Right now nothing in the draft makes the
submitter visible in the observability triplet (REQ-14).

---

## B5 — Keying any logic off `xb-status:*` labels is unsound; the draft half-sees this (BLOCKING for AC-33)

**Severity: blocking for AC-33; medium elsewhere.** Open Question 2 correctly
spots that crossbridge's status labels are inconsistent. The source confirms
it is worse than "inconsistent" — the three label transitions live in three
different binaries and never agree:

- `handle_submit` (server, `handler.rs:113`) applies `xb-status:open`.
- `handle_answer` (server, `handler.rs:201-206`) removes `xb-status:pending`
  and adds `xb-status:resolved` — but `pending` was never set by the server;
  it is set by the *client's* `submit_cmd` (`main.rs:125`,
  `labels::STATUS_PENDING`) on the *outbound* side.
- The client's `answer_cmd` (`main.rs:189`) applies `xb-status:answered` on
  the *inbound* side.

So on a vetinari *inbound* issue, the lifecycle is `xb-status:open` (set by
vetinari's own embedded server) and then `xb-status:answered` would be set by
whatever sends the answer. Crucially, **`xb-status:answered` is applied by
the client `answer` path, which the draft is reimplementing inside
`crossbridge_api` (REQ-20b / Open Question 4).** So vetinari controls whether
that label ever gets written. REQ-20g keying recovery off "lacks
`xb-status:answered`" is therefore keying off a label vetinari itself is
responsible for writing in the *same* step it is trying to make crash-safe —
if the crash happens after the answer round-trip succeeds but before the
label write, recovery re-sends (harmless, deduped) but the design has a
self-referential dependency it never acknowledges.

**Recommended change.** Make `phase_substate` in `state.db` the *sole*
authority for the answer step (consistent with REQ-2 — "Crosslink labels are
a presentation layer; the next-action decision MUST read from state.db"):

> REQ-20g (revised, supersedes the B3 wording too). The answer step's
> authority is the `phase_substate` column in `state.db`, never the
> `xb-status:*` label. The orchestrator writes `xb-status:answered` as a
> courtesy presentation label *after* `phase_substate` reaches `answer_sent`,
> but recovery and next-action logic read only `state.db`. The
> `xb-status:*` family is documented as unreliable (the four values —
> `open`, `pending`, `resolved`, `answered` — are written by three different
> crossbridge binaries with no shared state machine; see the upstream bug
> report below).

AC-33 must be rewritten to assert recovery off `phase_substate`, not off the
label.

Also act on Open Question 2's suggestion: **file an upstream bug** against
`vringar/crossbridge` describing the four-value `xb-status` incoherence
(`open`/`pending`/`resolved`/`answered`, written across server `handler.rs`
and client `main.rs`, never reconciled). The draft says "consider"; make it a
concrete deliverable referenced by REQ-20f's "finer-grained trust is filed
upstream" sentence.

---

## N1 — `crossbridge_api` insulation crate IS warranted — but for a different reason than the draft gives

**Severity: nice-to-have (the crate is correct; the *justification* is weak).**
The prompt asks whether `crossbridge_api` is ceremony. It is not — but the
draft's stated rationale ("mirroring REQ-3a/REQ-1c") undersells the real
need. REQ-3a/1c exist to contain *API churn* of an external lib. That
applies to crossbridge too, but the stronger reason is **B1**: tokio must be
quarantined. The orchestrator core is sync and tokio-free by deliberate
design; `crossbridge_api` is the membrane that lets `tokio`,
`crossbridge-server`, and the dedicated-runtime-thread machinery exist in the
binary without any of it leaking into `orchestrator/src/**`. That is a
genuine, load-bearing job — arguably more important than the churn-isolation
job, because a sync/async boundary is a real architectural seam, not just a
versioning convenience.

**Recommended change.** REQ-20b's first sentence should add: "and, critically,
to quarantine the `tokio` dependency and the async server surface from the
deliberately synchronous orchestrator core (root `Cargo.toml`: no async
runtime is pulled into the binary) — `crossbridge_api` is the only crate in
the workspace permitted to depend on `tokio`."

One real concern: `crossbridge_api`'s adapter surface "passes `crosslink`
issue/DB types across the boundary" (REQ-20b). It should not — that
re-exposes crosslink types and couples `crossbridge_api`'s signatures to
crosslink's API, undermining the insulation. The adapter should pass
vetinari-owned plain types (issue id, slug, comment text) and let
`crosslink_api` remain the *only* crate that names crosslink types. Recommend
adding a sentence to REQ-20b forbidding crosslink types in `crossbridge_api`'s
public signatures.

## N2 — Open Question 4: confirm reimplementing `answer`, but cost it honestly

**Severity: nice-to-have.** Reimplementing the ~30-line `answer` round-trip
(`crossbridge-client/src/main.rs:134-215`) on `crossbridge-protocol` types
inside `crossbridge_api` is the right call — option (c) shell-out is rightly
rejected, and option (b) upstream-export is a slow dependency. But note the
reimplementation is not purely the round-trip: `answer_cmd` also reads the
inbound issue's `kind=="result"` comments and the `xb-source:`/`xb-ref:`
labels from the crosslink DB to build the `SubmitAnswer`. That DB read must
go through `crosslink_api` (REQ-3a — single typed surface for crosslink), not
through a second crosslink handle opened by `crossbridge_api`. The draft's
architecture-deltas section says `answer(issue)` "wraps a
`crossbridge-protocol` round-trip"; it should say the comment/label
gathering is done by the orchestrator via `crosslink_api` and only the
`SubmitAnswer` wire round-trip lives in `crossbridge_api`. This keeps the
"single crosslink reader/writer surface" property intact.

Also: B1a already establishes that `run()` lacks a shutdown channel, so the
reimplementation surface in `crossbridge_api` may be larger than "answer
only" — fold that into Open Question 4's resolution.

## N3 — Edge case: two peers submitting the same upstream issue

**Severity: nice-to-have.** The prompt asks. crossbridge's `handle_submit`
idempotency is keyed on `xb-ref:<source_uuid>` (`handler.rs:95-105`), and
`source_uuid` is the *submitting repo's* issue UUID. Two different peers
submitting what is semantically "the same" upstream issue produce two
different `source_uuid`s, so vetinari gets **two distinct inbound issues**
and will drive both through the pipeline — duplicate work, and if auto-graph
is on, potentially two conflicting changes to `main`. This is not a crash, but
it is real waste. The draft should note it explicitly as accepted behavior
(crossbridge has no cross-peer dedup; vetinari inherits that) rather than
leave it unstated. A one-line entry under a new "Edge cases (accepted)"
subsection is enough. The same-peer resubmission case IS handled by
crossbridge's `xb-ref` idempotency — worth stating both.

## N4 — Edge case: in-flight submissions while the orchestrator is down

**Severity: nice-to-have.** While the orchestrator process is down, its
embedded server is also down (same process — B1). The per-peer listener
sockets are unlinked on shutdown (`listeners.rs` `Drop`/`clear`). A peer that
runs `submit` during that window gets "peer not available (not connected)"
(`client/main.rs:100`) — the submission simply fails fast on the peer side,
no issue is created, nothing is lost or half-written. This is actually clean
behavior and the draft should *state* it as the answer to the prompt's edge
case ("in-flight inbound submissions are not buffered; a submit while
vetinari is down fails fast peer-side and the peer retries") rather than
leave a reader to wonder whether there is a torn-write hazard. There is no
torn-write hazard at submit time because issue creation is a single
`db.transaction` in `handle_submit` — but the draft should still say so,
because REQ-3b's torn-write concern is otherwise a natural worry.

One genuine gap: REQ-20c says the server task starts "after state.db init and
the Z1 zellij bootstrap." If issue creation by the embedded server races the
orchestrator's own crash-recovery scan (REQ-15) at startup — the server could
create a new `xb:inbound` issue *while* `recovery.rs` is mid-scan — the
recovery scan might miss it or the pump might pick it up before recovery
finishes. **Recommend** REQ-20c explicitly sequence the server-task start
*after* the REQ-15 recovery scan completes, not merely after state.db init.

## N5 — Missing: what happens to the inbound issue's crosslink writes vs REQ-3 single-writer

**Severity: medium (closer to blocking-adjacent — flag for the canonical fold).**
REQ-3 states "single writer to crosslink": workers never write, the
orchestrator is the sole writer via `crosslink_api`. The embedded crossbridge
server **also writes crosslink** — `handle_submit` calls `create_issue`,
`add_label`, `add_comment` directly on a `crosslink::db::Database` it opens
itself (`run.rs:49`, `handler.rs:108-146`). That is a **second writer to
`.crosslink/issues.db`**, on a different thread, holding its own `Database`
handle, outside `crosslink_api`. The draft never reconciles this with REQ-3 /
REQ-3a.

This is probably *acceptable* (SQLite handles concurrent writers via its own
locking, and the server's writes are disjoint issue rows) but it is a real
amendment to a load-bearing invariant and must be called out, not glossed.

**Recommended change.** Add a REQ (e.g. REQ-20i) that explicitly amends
REQ-3:

> REQ-3 is amended: the embedded crossbridge server is a second writer to
> `.crosslink/issues.db`, by necessity (it owns inbound-issue creation). This
> is the *only* sanctioned second writer. It writes through crossbridge's own
> `crosslink::db::Database` handle, not through `crosslink_api`; the two
> writers are kept disjoint by construction — the server only ever creates
> new `xb:inbound` issues and applies their initial label set, and the
> orchestrator never writes an inbound issue's row until that issue has a
> `phase:*` label (i.e. until ingestion is complete). SQLite's file locking
> serializes the physical writes. The "single writer" property is preserved
> *per issue*; it is no longer literally true *per database*. AC-3 (workers
> cannot write crosslink) is unaffected — the server is not a worker.

Also confirm both writers use compatible SQLite settings (WAL vs rollback
journal, busy-timeout). If `crosslink_api` opens the DB in WAL mode and the
crossbridge `Database::open` does not (or vice versa), concurrent access can
fail with `SQLITE_BUSY` under load. This deserves an AC.

## N6 — AC coverage gaps

**Severity: nice-to-have.** The proposed AC-28..34 are reasonable but miss:

- No AC for B1's signal-handling isolation — add one: "SIGINT delivered to
  the orchestrator triggers the orchestrator's graceful shutdown (state.db
  checkpointed, recovery-clean); the embedded server thread does not
  short-circuit it via `process::exit`."
- No AC for B2's pin coherence (covered by the proposed AC-28a above).
- No AC for the never-converges / answer-on-failure case (B3) — add one:
  "an inbound issue driven to `phase:awaiting-human-merge` still sends an
  answer reporting the failure; the source repo's issue receives a
  `[from <slug>]` comment describing it."
- AC-34 ("supervisor-absent degradation") is good but should also assert the
  orchestrator still *shuts down cleanly* while the server task is mid-
  backoff-sleep — backoff is capped at 60s (`supervisor.rs:16`,
  `MAX_BACKOFF`), so a naive shutdown could block up to 60s waiting for the
  task. This ties back to B1a (no shutdown channel).

## N7 — Minor: `slug` derivation and the no-`origin` case

**Severity: nice-to-have.** REQ-20a says `slug` "overrides origin-remote
derivation for repos with no `origin`." Crossbridge derives the slug via
`crossbridge-client::slug::derive_own_slug` and `crossbridge-server`'s own
`slug` module. The draft should confirm `crossbridge_api` uses crossbridge's
`slug` derivation as the default (so vetinari and a peer agree on vetinari's
slug) and only falls back to the config override when derivation fails —
rather than vetinari inventing its own slug logic, which would desync from
how peers address it. One sentence in REQ-20a.

---

## Summary of required changes before the fold

Blocking:
- **B1 / B1a** — rewrite REQ-20c: dedicated thread + own current-thread
  runtime; resolve the missing-shutdown-channel problem (upstream issue or
  reimplement `run`); fix the `process::exit` signal-handling hazard.
- **B2** — rewrite REQ-20b's pin-unification para: same-commit constraint,
  three-way coordinated bumps, add AC-28a pin-coherence check; state whether
  vetinari forks crossbridge.
- **B3** — rewrite REQ-20e/20g: `answer_unreachable` substate, bounded
  per-tick retry, answer-on-failure-terminal-phase so peers are never left
  hanging; remove the unbounded forever-retry.
- **B4** — resolve `auto_graph`: either drop it (Option A, preferred) or
  redefine it to never auto-land (Option B, `phase:awaiting-inbound-
  approval`); fix the now-false trust sentence in REQ-20f.
- **B5** — make `phase_substate` the sole authority for the answer step;
  stop keying recovery off `xb-status:answered`; file the upstream
  status-label bug.
- **N5** (promoted) — explicitly amend REQ-3: the embedded server is a
  sanctioned second crosslink writer; document the disjoint-by-construction
  argument and SQLite journal-mode compatibility.

Nice-to-have:
- N1 (justify `crossbridge_api` by tokio quarantine; forbid crosslink types
  in its signatures), N2 (answer reimpl scope + route DB reads through
  `crosslink_api`), N3 (two-peer duplicate submission — document as
  accepted), N4 (down-time submit behavior + sequence server start after
  recovery scan), N6 (AC gaps), N7 (slug derivation).

Sound as-is: the role-3 scoping decision and the rejection of roles 1 and 2;
the config-gating shape of REQ-20a (`enabled` default false, absent section
== disabled); the decision to not start `crossbridge-supervisor` from the
orchestrator (REQ-20c); npins-pinning crossbridge with explicit-issue bumps.
