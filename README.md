# vetinari

A long-running, headless orchestrator for **Verification-Driven Development (VDD)**. Vetinari drives issues in a [crosslink](https://github.com/forecast-bio/crosslink) tracker through a deterministic pipeline — implement → static QA → adversary review → converge → land — using `claude` workers isolated in `bwrap` sandboxes and [jj](https://github.com/jj-vcs/jj) workspaces. The orchestrator owns every state transition and is the single writer to crosslink; workers only produce artifacts on disk. All authoritative state lives in a SQLite database, so the orchestrator is crash-safe: kill it mid-tick and it re-derives the truth from the filesystem on restart. It has demonstrated self-hosting — a real `claude` worker, orchestrator-driven, landed a change end-to-end and headlessly.

## How it works

Each issue advances through an orchestrator-owned phase machine:

```
graphed → implementing → qa-gate → adversary-review → converged → landing → merged
```

- **graphed** — the build pump picks up issues explicitly labeled `phase:graphed` (humans decompose and file them via `/design` and `crosslink subissue`; the orchestrator does not run a refinement pump).
- **implementing** — a fresh `claude` Implementer worker is spawned in an isolated jj workspace, commits its change, and exits. Every round is a brand-new invocation; prior adversary findings are passed as a task-input file, never as session memory.
- **qa-gate** — the orchestrator runs `.orchestrator/static_qa.sh` against the worker's tree. The verdict is **owned by exit code**, never by the worker: exit 0 advances; non-zero is captured as a `--kind blocker` comment and the Implementer is re-spawned fresh with that blocker as input.
- **adversary-review** — a fresh Adversary worker reads a pre-rendered diff and prior findings and emits `findings.jsonl`. Non-empty findings send the issue back to `implementing`; empty findings count toward convergence.
- **converged** — reached when the convergence detector observes **N consecutive clean adversary rounds** (default `n_rounds = 2`) on the issue's fixed change. Convergence is computed by the orchestrator, never declared by a worker. (Static QA runs once per *implement* round in the `qa-gate` phase, before adversary review — not per adversary round. The `last_diff_hash` column is reserved for a future concurrent/async model and is not part of today's convergence signal.)
- **landing** — the orchestrator lands the change from **outside any sandbox**. In local mode (crosslink's `tracker_remote` unset) it rebases the issue's change onto `main` and fast-forwards the `main` bookmark; the fast-forward guard means landing can never clobber `main`. On a rebase conflict it moves the issue to a crash-safe `merging` substate, spawns a Merger worker to resolve the conflict, re-runs static QA on the merged tree, and retries the fast-forward once; if that fails the issue parks at `phase:awaiting-human-merge`. In remote mode (`tracker_remote` set) it instead pushes a `vdd/<id>-<slug>` branch and opens a GitHub PR → `phase:pr-open`.
- **merged** — terminal.

Two ideas hold the whole thing together:

1. **The orchestrator is the single writer and owns the verdict.** Workers cannot mutate crosslink or decide their own success. QA is decided by process exit code; convergence by N clean adversary rounds; landing by a guarded fast-forward. The orchestrator translates worker artifacts into signed, typed crosslink comments (`plan | decision | observation | blocker | resolution | result`).
2. **Workers are guardrailed, but the real safety is orchestrator-side.** Each worker runs in a `bwrap` sandbox with a kernel-enforced per-role mount matrix (the Implementer sees `.jj/` but never `.git/` or `.orchestrator/`; the Adversary sees neither `.jj/` nor `.git/`) and a per-role tool allowlist. The sandbox is a guardrail — but the load-bearing protection for `main` is orchestrator-side validation *before* landing: static QA, adversary review, and a fast-forward-guarded merge.

Every worker writes a `_orchestrator/DONE` sentinel as its last filesystem operation. Absence of `DONE` is treated as a crash regardless of exit code, which catches torn-write partial failures; a `posted_artifacts` table makes artifact→comment translation idempotent across restarts.

## Architecture

A cargo workspace of six crates:

| Crate | Role |
|-------|------|
| `crates/orchestrator` | The main binary. Modules: `pump` (poll → pick → dispatch), `spawn` (per-role `bwrap` worker + zellij hosting), `qa` (static-QA runner), `artifacts` (worker artifact contract + DONE sentinel), `landing` (local rebase / fast-forward, Merger-retry on conflict, and remote branch-push + `octocrab` PR open), `recovery` (deterministic crash-recovery table), `roles` (Implementer / Adversary / Merger allowlists + prompts), `events` (append-only `events.jsonl`), `state` (SQLite `state.db`), `workspace`, `config`. |
| `crates/crosslink_api` | Insulation crate wrapping the crosslink library behind a stable adapter surface (issue read, signed comment write, labels). Absorbs crosslink API churn so the rest of the orchestrator does not move. |
| `crates/jj_api` | Insulation crate wrapping `jj-lib` — workspace add/forget, status, diff, log, rebase, bookmark, git push — behind a synchronous adapter surface. |
| `crates/zellij_host` | Wraps the `zellij` CLI to host each worker in a named pane inside a long-lived headless `vdd-orchestrator` session, so a human can `zellij attach` and inspect a stuck worker live. |
| `crates/error` | Common `miette::Diagnostic` error types (published as `vetinari-error`). |
| `crates/xtask` | The "no shell-out" hard lint: fails the build if orchestrator-side code shells out to `jj`, `git`, `gh`, `crosslink`, or `zellij` instead of going through the library adapters. |

**Substrate:** crosslink (issue tracker + signed comments), jj (version control, via `jj-lib`), bwrap (worker sandbox), zellij (worker hosting), nix (pinned toolchain). Workers drive `jj` as a CLI inside their sandbox because Claude's tool surface is shell-based; the orchestrator itself reaches jj, crosslink, and GitHub only through the insulation crates (`jj-lib`, `octocrab`, `crosslink_api`) — the sole sanctioned shell-outs are spawning `claude`, the `zellij` CLI in `zellij_host`, and the user-supplied `static_qa.sh`.

## Status

The core loop works, is crash-safe, and self-hosts:

- **Full local loop green.** `graphed → implementing → qa-gate → adversary-review → converged → landing → merged` runs headlessly against a fixture (AC-11a) and drives real `claude` workers.
- **Crash safety.** The durable state is on disk (`.orchestrator/state.db` + `events.jsonl`); the orchestrator re-derives truth from these on restart. A heartbeat-based watchdog staleness check is supported and read orchestrator-side, but per-worker heartbeat *writing* (the worker PostToolUse hook, REQ-11) is not yet wired. Recovery is idempotent — running it twice produces the same final state. Covered by integration tests for worker-phase rollback, mid-translation restart, and landing-substate resumption.
- **Self-hosting demonstrated.** A real `claude` Implementer, orchestrator-driven, landed a change end-to-end on this repo's substrate (AC-11b). This test is `#[ignore]`d and gated behind `VETINARI_LIVE_CLAUDE=1` because a live agent is slow, nondeterministic, and spends API budget.
- **Iteration-2 adversary loop landed.** The Adversary role, the `adversary-review` phase in the pump, and the N-consecutive-clean-rounds convergence detector are all in.

Landing conflict-resolution and remote mode are in:

- **Merger role.** On a local-mode rebase conflict the orchestrator moves the issue to a crash-safe `merging` substate, spawns a Merger worker (a jj-resolve-focused allowlist with a `.jj/`+`.git/` RW mount) to resolve the conflict, re-runs static QA on the merged tree, and retries the fast-forward landing **once**. If the Merger fails, QA fails, or the tree still conflicts, the issue parks at `phase:awaiting-human-merge`.
- **Remote-mode landing.** When crosslink's `tracker_remote` is set, landing pushes a `vdd/<id>-<slug>` branch and opens a GitHub PR via the `octocrab` library (not a `gh` subprocess) → `phase:pr-open`. A crash-safe substate machine (`push_started → push_done_pr_pending → pr_created`) is wired into recovery, so a crash mid-landing resumes rather than quarantining, and PR creation is idempotent (a resume adopts an existing head PR instead of double-opening). The local fast-forward path remains the default, selected when `tracker_remote` is unset. PR creation is exercised in tests through a seam — deterministic runs push to a local bare origin with a fake PR-opener — so the live GitHub path, while real, is not covered by a live CI test.

Known / remaining:

- **Worker isolation is accept-trust today.** A live worker has network access and credentials; the sandbox mount matrix is a guardrail, not a containment boundary. Protection for `main` is orchestrator-side: static QA + adversary review + a fast-forward-guarded landing that runs entirely outside any sandbox.

## Build & run

Everything runs inside the nix dev shell, which pins the toolchain (rustc, jj, zellij, bwrap, sqlite, python, gh) and exposes the crosslink and jujutsu source trees. Entering the shell auto-runs `just bootstrap` to wire those source paths into the cargo build.

```sh
nix-shell            # enter the dev shell (or use direnv)

just build           # cargo build --workspace --all-targets
just test            # nextest if available, else cargo test --workspace
just lint            # rustfmt --check + clippy -D warnings + xtask no-shell-out lint
just fmt             # apply formatting

just orchestrate     # run the orchestrator against this repo (cargo run --release -p orchestrator)
just dogfood         # AC-11a fixture dogfood: drive one issue graphed → merged headless
just graph           # crosslink: what's blocked + what's ready to work on
```

The live-claude self-host test is opt-in — it is `#[ignore]`d and only runs when gated on:

```sh
VETINARI_LIVE_CLAUDE=1 cargo test -p orchestrator --test dogfood_ac11b -- --ignored --nocapture
```

The dev shell uses a classic `shell.nix` with dependencies pinned via **npins** (`npins/sources.json`); nix flakes are deliberately avoided. `just bootstrap` regenerates `.cargo/config.toml` (redirecting `jj-lib` to the pinned jujutsu source) and stages a writable copy of the pinned crosslink source at `.crosslink-src` — both are per-host and git-ignored.

## License

Licensed under either of **MIT** or **Apache-2.0** at your option (`MIT OR Apache-2.0`).
