# Design: Crossbridge integration (role 3 — inbound server peer)

> **Status:** DRAFT — pending the-architect review. Once reviewed and applied,
> the finalized REQ/AC set folds into `vdd-orchestrator.md` and this file is
> retired. Resolves crosslink issue #25.

## Decision (issue #25)

Issue #25 asked which of three candidate crossbridge roles vetinari should adopt:

1. **Cross-instance coordination** — multiple vetinari instances share host-wide state.
2. **Worker cross-repo Q&A** — sandboxed workers ask agents in other repos mid-task.
3. **Inbound submissions** — vetinari registers a crossbridge server and answers
   submissions routed to it from peer repos.

**Adopted: role 3 only.** Rejected:

- **Role 2** breaks the design's central invariant — worker hermeticity (REQ-6/7/8).
  Mid-phase Q&A to external agents introduces non-determinism that the fresh-context
  model (REQ-8), idempotent translation (REQ-3b), and crash recovery (REQ-15) all
  depend on *not* existing. It also requires binding the crossbridge socket directory
  into `claude-sandbox` (a new escape vector out of the sandbox). Worst fit.
- **Role 1** is speculative — nothing in the design runs multiple vetinari instances,
  and no concrete shared state was identified.

Role 3 runs entirely **orchestrator-side, outside any sandbox**, so the known hard
constraint (the crossbridge socket root is not bind-mounted into `claude-sandbox`)
does not apply.

## What crossbridge is (verified against `vringar/crossbridge` source)

Crossbridge federates **crosslink issues** across repos on one host:

- `crossbridge-supervisor` — per-host singleton; owns `<root>/register.socket` and the
  `group → slug → socket` topology. Ships as a `crossbridge-supervisor.service` unit.
- `crossbridge-server --group <g> --slug <s>` — per-repo; registers with the supervisor
  and owns one repo's `.crosslink/issues.db`. Long-lived daemon.
- `crossbridge-client {peers, submit, answer}` — per-agent CLI.

Lifecycle: repo A runs `submit --issue X --target B`; B's server creates a local
crosslink issue carrying `type:request`, `xb:inbound`, `xb-status:open`,
`xb-source:<A>`, `xb-ref:<uuid>`. When B finishes, `answer --issue X` ships B's
`kind=result` comments back to A's issue (copied with a `[from <slug>]` prefix,
deduped by content), flips status, and closes both sides.

Crucially, crossbridge exposes **real Rust library crates**:
`crossbridge-protocol` (pure lib — wire types + framing), `crossbridge-server`
(`lib.rs` exposes `run::run(ServerConfig)` + `handler::{handle_submit,handle_answer}`),
and `crossbridge-client` (`lib.rs` exposes `labels`, `peers`, `slug`). The CLI
binaries are thin wrappers. This means vetinari can integrate **with no shell-out**.

## Requirements (proposed — REQ-20 series)

- **REQ-20 (crossbridge role = inbound server peer).** Vetinari MAY register as a
  crossbridge server peer so other repos in its peer group can submit crosslink
  issues to it. The orchestrator drives inbound issues through the *same* VDD
  pipeline as local issues and, on completion, answers the result back to the
  source repo. This is the only crossbridge role adopted (issue #25); roles 1 and 2
  are explicitly rejected. Crossbridge is optional and config-gated (REQ-20a); the
  MVP fixture and self dogfoods (AC-11a/11b) run with crossbridge disabled.

- **REQ-20a (config gating).** A `[crossbridge]` section in `.orchestrator/config.toml`:
  `enabled` (bool, default `false`), `group` (peer-group name), `slug` (this repo's
  crossbridge slug — overrides origin-remote derivation for repos with no `origin`),
  `auto_graph` (bool, default `false`). With `enabled = false` the orchestrator never
  starts the server task, never registers, and never attempts an answer; all
  crossbridge code paths are inert. Absence of the section is equivalent to disabled.

- **REQ-20b (crossbridge via a `crossbridge_api` insulation crate — no shell-out).**
  Mirroring REQ-3a (crosslink) and REQ-1c (jj): an in-repo `crates/crossbridge_api`
  crate wraps the `crossbridge-server`, `crossbridge-client`, and `crossbridge-protocol`
  library crates behind a stable adapter surface owned by this repo. The orchestrator
  never depends on crossbridge crates directly outside `crossbridge_api`. Because
  crossbridge ships real libraries, integration is **in-process**: the orchestrator
  runs the server via `crossbridge-server`'s `run()` and sends answers via
  `crossbridge-protocol`'s wire types on its own tokio runtime. There is therefore
  **no new shell-out** and **no addition to the AC-24 lint** — unlike `zellij`
  (REQ-1d), crossbridge has a stable library form, so the zellij CLI-wrapper
  precedent does not apply here. crossbridge is pinned by npins (a new
  `crossbridge` source → `vringar/crossbridge`) and exposed to cargo via the
  nix-generated `.cargo/config.toml`, exactly as crosslink is (REQ-1, REQ-3a).
  Bumping the pin is an explicit issue.
  - **Crosslink-pin unification (hard constraint).** `crossbridge-server` itself
    git-depends on `crosslink`. For the orchestrator to embed `crossbridge-server`
    *and* use `crosslink_api` (REQ-3a), both MUST link the *same* `crosslink` crate
    instance — `crossbridge_api` passes `crosslink` issue/DB types across the
    boundary, and two git revisions of `crosslink` would be two incompatible types.
    The nix dev shell MUST provide a single `crosslink` source path, and the
    generated `.cargo/config.toml` MUST `[patch]` crossbridge's `crosslink` git
    dependency to that same path. The npins `crosslink` and `crossbridge` pins must
    be chosen so their crosslink revisions reconcile.

- **REQ-20c (embedded server lifecycle).** When `crossbridge.enabled`, the
  orchestrator runs `crossbridge-server`'s `run()` as a supervised background task
  on its tokio runtime, started after `state.db` init and the Z1 zellij bootstrap.
  The orchestrator does **not** start `crossbridge-supervisor` — it is a host-wide
  singleton shared by all peers; starting it from the orchestrator would race other
  peers. If the supervisor is unreachable the embedded server retries with backoff
  (crossbridge's own behavior) and the orchestrator's build pump is unaffected,
  continuing to drive local issues. If the server task returns a fatal error (e.g.
  a slug-collision `Nack`), the orchestrator emits a `crossbridge_degraded` event,
  marks crossbridge degraded for the process lifetime, and continues without it —
  it does NOT crash the orchestrator. The server requires the project's
  `.crosslink/issues.db` to exist (it always does — the orchestrator's own crosslink
  use guarantees it).

- **REQ-20d (inbound issue ingestion — no auto-graph by default).** The embedded
  server creates inbound issues directly in `.crosslink/issues.db` with crossbridge's
  marker labels and NO `phase:*` label. Per Q1, the build pump ignores unphased
  issues, so an inbound issue sits untouched until a `phase:graphed` label is
  applied. By default that label is applied by a human reviewing the inbound issue
  (the same explicit opt-in as local issues, REQ-16). When `crossbridge.auto_graph
  = true`, the orchestrator instead applies `phase:graphed` to every new `xb:inbound`
  issue automatically — making a peer-submitted issue trigger autonomous
  implement-and-land with no human in the loop. `auto_graph` defaults `false`; it
  MUST only be enabled for a fully-trusted peer group (REQ-20f).

- **REQ-20e (answer-back on completion).** An issue carrying `xb:inbound` that reaches
  a terminal phase (`phase:merged` or `phase:pr-open`) gets one additional landing
  substep: the orchestrator posts a `--kind result` summary comment (sourced from
  the issue's `result.md` / landing outcome) and then sends a crossbridge answer to
  the source repo, routing the issue's `kind=result` comments back via the
  `xb-source:`/`xb-ref:` labels. The substep is tracked as a `phase_substate`
  (REQ-2a): `answer_pending` → `answer_sent`. On success the orchestrator applies
  `xb-status:answered` and closes the issue, matching `crossbridge-client answer`
  semantics. The answer round-trip is performed in-process through `crossbridge_api`
  (REQ-20b). Local (non-inbound) issues skip this substep entirely.

- **REQ-20f (trust posture).** Crossbridge's trust boundary is the peer group: any
  server in the group can submit to any peer, the submitting `peer_slug` is derived
  from the socket path and is NOT cryptographically authenticated, and there is no
  per-peer allowlist. The orchestrator therefore treats group membership as *the*
  trust boundary and documents it plainly: enabling `crossbridge.enabled` means
  trusting every current and future member of `crossbridge.group` to file issues
  into this repo's tracker; enabling `crossbridge.auto_graph` additionally means
  trusting them to trigger autonomous code changes that land without human review.
  The safe default (`auto_graph = false`) keeps a human gate on every inbound issue.
  The orchestrator does not add its own authentication layer — that is a
  crossbridge-layer concern; finer-grained trust is filed upstream against
  `vringar/crossbridge`.

- **REQ-20g (crash-safe answer).** The answer substep is idempotent and crash-safe
  per REQ-15. crossbridge's `handle_answer` dedups copied comments by content on the
  source side, so re-sending an answer is safe. On orchestrator restart, recovery
  (`recovery.rs`) treats an `xb:inbound` issue in a terminal phase that lacks the
  `xb-status:answered` label as `answer_pending` and re-sends. Recovery is
  idempotent: a second answer is deduped source-side and produces the same final
  state.

## Acceptance Criteria (proposed — AC-28 series)

- **AC-28 (disabled by default).** With no `[crossbridge]` section (or `enabled =
  false`), the orchestrator starts, runs the fixture dogfood (AC-11a) to completion,
  and never opens a crossbridge socket or registers with a supervisor. Verified: no
  `crossbridge` event in `events.jsonl`; AC-11a still passes.
- **AC-29 (embedded server registration).** Integration test: with a test supervisor
  on an isolated `CROSSBRIDGE_SOCKET_ROOT` and `crossbridge.enabled = true`, the
  orchestrator's embedded server registers under the configured slug/group;
  `crossbridge-client peers` from a second test repo lists vetinari's slug.
- **AC-30 (inbound ingestion + manual graph).** Integration test: a peer test repo
  runs `submit --issue X --target <vetinari-slug>`. The issue appears in vetinari's
  `.crosslink/issues.db` with `xb:inbound`/`xb-source:`/`xb-ref:` labels and no phase
  label; the pump does not pick it up. After `phase:graphed` is applied, the pump
  dispatches an Implementer for it.
- **AC-31 (auto-graph opt-in).** Integration test: with `auto_graph = true`, a
  freshly-submitted inbound issue receives `phase:graphed` automatically and is
  dispatched with no human action; with `auto_graph = false` the same submission
  stays unphased.
- **AC-32 (answer-back on completion).** End-to-end fixture test: an inbound issue is
  graphed, driven to `phase:merged`, and answered; the source test repo's originating
  issue receives the `[from <slug>]` result comment(s) and is closed; vetinari's
  inbound issue carries `xb-status:answered` and is closed. Verified via
  `events.jsonl` showing `answer_pending → answer_sent`.
- **AC-33 (answer crash-safety).** Kill the orchestrator between reaching
  `phase:merged` and the answer being sent (`answer_pending`). On restart, recovery
  detects the missing `xb-status:answered` label and re-sends; the source repo's
  issue shows the result comment exactly once (source-side dedup). Re-running
  recovery is a no-op.
- **AC-34 (supervisor-absent degradation).** With `enabled = true` but no supervisor
  running, the orchestrator starts, emits a `crossbridge_degraded` event, drives
  local `phase:graphed` issues normally, and the embedded server task retries in the
  background without affecting the pump.

## Architecture deltas

- **New crate `crates/crossbridge_api`** — insulation crate (REQ-20b). Adapter
  surface: `serve(cfg) -> task handle` (wraps `crossbridge-server::run`),
  `answer(issue) -> Result<()>` (wraps a `crossbridge-protocol` round-trip — the
  client-side `answer` logic lives in crossbridge's `client/src/main.rs`, not its
  `lib.rs`, so the ~30-line round-trip is reimplemented on `crossbridge-protocol`
  types; see Open Question 4), and label helpers re-exported from
  `crossbridge-client`'s `labels` module.
- **New npins source `crossbridge`** in `npins/sources.json` → `vringar/crossbridge`,
  surfaced through `shell.nix` and the generated `.cargo/config.toml`, with the
  `[patch]` for crosslink-pin unification (REQ-20b).
- **New orchestrator module `crates/orchestrator/src/crossbridge.rs`** — owns the
  supervised server task, the `auto_graph` ingestion poll, and the answer step;
  invoked from `main.rs` startup and from `landing.rs`.
- **`landing.rs`** gains the answer substep for `xb:inbound` issues (REQ-20e).
- **`recovery.rs`** gains the `answer_pending` recovery row (REQ-20g).
- **`state.db`** — the `phase_substate` value set gains `answer_pending`,
  `answer_sent`. No schema change (the column already exists, REQ-2a).
- **`config.rs`** — parses the new `[crossbridge]` section.
- **`events.rs`** — new event kinds: `crossbridge_register`, `crossbridge_degraded`,
  `crossbridge_inbound`, `crossbridge_answer`.

## Open questions for the-architect

1. **Trust / auto-graph.** Is `auto_graph` worth shipping at all, given crossbridge
   has no per-peer authentication? Alternative: drop `auto_graph` entirely and always
   require a human to graph inbound issues. Or: keep it, but force inbound issues to
   land via PR (`phase:pr-open`, human review) regardless of `tracker_remote` mode —
   so even auto-graphed inbound work never auto-merges. Landing mode is currently
   global (REQ-17); a per-issue override for inbound issues would be new surface.
2. **crossbridge status-label inconsistency.** The server applies `xb-status:open`
   on submit (`handler.rs`), but `handle_answer` swaps `xb-status:pending →
   xb-status:resolved`, and the client marks `xb-status:answered`. Four status
   values, inconsistently used. Vetinari should key off `xb:inbound` presence +
   issue open/closed, not the status sub-label. Confirm; consider an upstream bug
   report.
3. **Crosslink-pin unification** (REQ-20b) — is the cargo `[patch]` approach sound,
   or does this argue for vetinari and crossbridge sharing a pinned crosslink via a
   single npins entry that crossbridge also consumes? This is the riskiest wiring.
4. **Reimplementing `answer`'s client round-trip.** crossbridge's client `answer`
   logic is in `main.rs`, not exposed by `crossbridge-client`'s `lib.rs`. Options:
   (a) reimplement the ~30-line round-trip on `crossbridge-protocol` types inside
   `crossbridge_api`; (b) file upstream to export `answer` from the client lib;
   (c) shell out to `crossbridge-client answer` (rejected — reintroduces shell-out).
   Draft picks (a). Confirm.
5. **Server task vs. orchestrator runtime.** The embedded server is a long-lived
   tokio task. Does the orchestrator already have a tokio runtime, or is it
   currently sync? If sync, embedding the server forces a runtime — weigh against a
   dedicated thread running its own current-thread runtime.
