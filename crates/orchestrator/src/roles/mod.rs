//! Worker **role definitions** — the concrete tool allowlist, system prompt,
//! and turn cap each [`WorkerRole`](crate::state::WorkerRole) runs under (S7).
//!
//! [`crate::spawn`] provides the *mechanism* — how a `claude` worker is hosted
//! in a `bwrap` sandbox with a per-role mount matrix, a caller-supplied
//! `--allowed-tools` value, a `--disallowed-tools` deny list, a system prompt,
//! and a `--max-turns` cap. This module supplies the *policy*: the exact values
//! those knobs take for a given role. Keeping the two apart means the spawn
//! layer stays a pure argv assembler, and the security-relevant allowlist +
//! deny list live in one auditable place.
//!
//! # THREAT MODEL — what protects `main`, and what does not
//!
//! Be honest about the security model, because an earlier version of these docs
//! was not: **the tool allowlist is NOT a hard isolation boundary around a
//! malicious worker.** Two facts make that plain, both consequences of the
//! direct-`bwrap` rework in which the Implementer/Merger sandbox binds the
//! repository `.jj/` **and** the colocated `.git/` read-write (a colocated jj
//! backend cannot open the repo otherwise — [`crate::spawn`]'s finding #1):
//!
//! - `Bash(cargo test)`/`Bash(cargo build)` run **arbitrary compiled code**, and
//!   `Write`/`Edit` can touch the RW-mounted `.jj/`/`.git/`. A determined worker
//!   can therefore reach and corrupt the VCS store **without ever typing a
//!   denied `jj` verb** — so no jj-verb allowlist can "cage" it.
//! - A real `claude` worker inherently needs network egress (the Anthropic API)
//!   and credentials to run at all, so "no network / no secrets" is not a
//!   property this sandbox has today.
//!
//! **What actually keeps a bad outcome off `main` is ORCHESTRATOR-SIDE
//! VALIDATION** — every mechanism that vets a change *before* it can touch
//! trunk:
//!
//! - the **static QA gate** (S5), run on the worker's tree before landing;
//! - the **fast-forward-guarded local landing** (L2): `main` can only *advance*
//!   to a descendant of trunk, never be rewound or force-moved, so even a
//!   corrupt or malicious change cannot rewrite trunk history; and
//! - **adversary review** of the diff (iteration 2).
//!
//! Against that backdrop the tool allowlist ([`implementer::ALLOWED_TOOLS`]), the
//! `--disallowed-tools` deny list ([`implementer::DISALLOWED_TOOLS`]), and the
//! `bwrap` mount matrix are **defense-in-depth guardrails**: they reduce
//! *accidental* damage and make the intended `jj` commit path the easy one. They
//! are explicitly **NOT** a cage around a determined, malicious worker.
//!
//! A note on the deny list vs. the allowlist: `--permission-mode default` does
//! not cleanly *deny* an unlisted tool — it **asks**, and a headless worker (no
//! stdin) cannot answer, so the call wedges until the pump's `worker_timeout`
//! catches the stall as a crash. The `--disallowed-tools` entries give the
//! known-dangerous verbs a *clean* refusal (no prompt, no hang); the timeout is
//! the backstop for everything else.
//!
//! # KNOWN LIMITATION / FOLLOW-UP (requires a design decision — NOT built here)
//!
//! True worker hardening is a documented follow-up, deliberately out of scope
//! for S7 because it needs a design decision (topology, credential model,
//! failure modes):
//!
//! - **egress filtering** so a worker can reach *only* the Anthropic API, not
//!   arbitrary hosts;
//! - **scoped, ephemeral credentials** rather than the operator's ambient auth;
//! - an **isolated object store** the worker cannot use to corrupt the shared
//!   repository (e.g. a per-worker clone landed back under orchestrator control).
//!
//! Until that lands, the guardrails above plus orchestrator-side validation are
//! the whole story, and this module claims nothing stronger.
//!
//! Only the Implementer role is defined here for the MVP (S7); the Adversary,
//! Merger, and Judge roles are iteration-2+ and land with their own modules.

pub mod implementer;
