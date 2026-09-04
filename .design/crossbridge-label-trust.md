# Crossbridge inbound-label trust (the label-echo gap + our defense)

Durable record of a security investigation into whether an untrusted crossbridge
peer can defeat the REQ-SWARM-1 inbound approval gate by planting its own
`inbound-approved:land` label. **Verdict: it could — upstream echoes peer labels
verbatim — so the orchestrator now strips them on first adoption.**

## The question

The step-6 land gate (`orchestrator::pump::BuildPump::land`) parks any `xb:inbound`
issue that does **not** already carry `inbound-approved:land`, and lands one that
does (reading the label as a human's approval). So: can a peer's `submit` cause
`inbound-approved:land` (or `phase:*` / `xb-status:*`) to be present on the
`xb:inbound` issue the embedded server creates?

## The evidence trail (pinned crossbridge `iy4j9v4…-source`, npins rev `479d468`)

1. **The wire request carries peer-controlled labels.**
   `crossbridge-protocol/src/lib.rs` — `struct SubmitIssue` has
   `pub labels: Vec<String>` (alongside `title`, `body`, `source_slug`,
   `source_uuid`, `attachments`). A peer sets these freely.

2. **The server echoes them onto the created issue.**
   `crossbridge-server/src/handler.rs` — `handle_submit` builds the label set as
   five server-derived labels (`type:request`, `xb:inbound`, `xb-status:open`,
   `xb-source:<submit.source_slug>`, `xb-ref:<source_uuid>`) and then:

   ```rust
   // Include any extra labels the client requested, deduped against ours.
   for l in &submit.labels {
       if !labels.iter().any(|existing| existing == l) {
           labels.push(l.clone());
       }
   }
   ```

   The dedup is only against those five names. There is **no allowlist / denylist**
   — `inbound-approved:land`, any `phase:*`, and any `xb-status:*` other than the
   server's own `xb-status:open` pass straight through onto the issue.

3. **Consequence.** A hostile peer submits with
   `labels = ["inbound-approved:land", "phase:graphed", ...]`. Once the issue is
   graphed and driven to convergence, `land` reads its own planted approval and
   auto-lands untrusted work — exactly the "untrusted origin ⇒ HARD NO-GO on
   auto-land" boundary the gate exists to enforce. `xb-source:<slug>` is likewise
   peer-supplied (not authenticated), reinforcing that no inbound label is trusted.

## The defense (orchestrator side — never trust a peer label)

We do not patch crossbridge (vendored/regenerated). Instead the pump neutralizes
peer labels the first time it adopts an inbound issue, before any gate reads them:

- `pump::is_peer_forbidden_inbound_label` classifies the privileged set:
  `inbound-approved:land`, `followup:proposed`, any `phase:*` except `phase:graphed`,
  any `xb-status:*` except `xb-status:open`.
- `pump::BuildPump::sanitize_inbound_labels` strips them via `crosslink_api`
  `label_remove` only (AC-24: no shell-out) and emits an audit event per strip.
- Wired in `BuildPump::ingest`, **inside** the `state.db`-untracked branch and
  guarded by `answer::is_inbound` — so it runs exactly **once**, at first adoption,
  before the row is seeded and before any drive/land. A *human's* later
  `inbound-approved:land` (only ever applied after the issue parks) is never
  stripped. Re-poisoning is impossible: a peer's only write path is a duplicate
  `submit`, which `handle_submit` short-circuits on `xb-ref:<uuid>` and re-applies
  no labels.

`phase:graphed` and `xb-status:open` are preserved as legitimately server/chief-set
(the former is also the ingest trigger; the pump's phase mirror owns it thereafter).

## Residual note (flagged, not fixed here)

Stripping happens at first adoption, which for the self-graphing case is after
ingest already keyed off a peer-set `phase:graphed` — so a peer *can* still get its
issue **driven** without human triage (wasted compute). It still **parks** and
never auto-lands (its approval is stripped), so the security boundary holds. DAG /
blocker labels are also not stripped (graphing is the trusted chief's job); a peer
planting dependency labels to perturb the DAG is out of scope for this gate.

## Tests

- `pump::tests::peer_forbidden_inbound_label_classifies_the_privileged_set` — the
  classifier (strip the privileged set; preserve server/chief labels; exact-match,
  no prefix false-positives).
- `tests/inbound_approval.rs::ingest_strips_a_peer_preset_approval_so_the_gate_still_parks`
  — an inbound issue arriving with `inbound-approved:land` (+ `phase:graphed`,
  `followup:proposed`, bogus `xb-status:`) has them stripped by the real ingest
  path (`tick`, budget 0), the legitimate labels survive, and the issue then
  **parks** at `awaiting-inbound-approval` instead of auto-landing.
