# Threat Model: Worker Isolation for Unsupervised Auto-Landing

Scope: the vetinari VDD orchestrator, ahead of enabling unsupervised auto-landing. Question: once a malicious/adversarial issue can drive a worker end-to-end, what can that worker reach, and what lands on `main`?

Method: grounded in the actual spawn/verify code. Every mount, flag, and exec site is cited `file:line`. Where the design's own docstrings already admit a hole, that is quoted — the code is honest; the gap is real, not theoretical.

---

## 1. Attack surface map (grounded in code)

### 1a. The worker sandbox (bwrap) — what a worker CAN reach

Base mount policy: `SandboxHost::base_mounts`, `crates/orchestrator/src/spawn.rs:1034-1086`.

| Flag | Line | Effect | Assessment |
|------|------|--------|-----------|
| `--tmpfs <home>` | :1038 | empty HOME, operator's home shadowed | good |
| `--ro-bind /nix /nix` | :1040 | whole nix store readable | acceptable (world-readable store) |
| `--ro-bind /etc /etc` | :1043 | **entire host `/etc` readable** | over-broad; see T6 |
| `--proc /proc` | :1046 | fresh procfs | good |
| `--dev /dev` | :1048 | bwrap minimal devtmpfs (NOT host /dev) | good |
| `--tmpfs /run`, `--tmpfs /tmp` | :1050-1052 | private scratch | good |
| `--symlink <sh> /bin/sh` | :1054 | /bin/sh | good |
| RO binds: `~/.nix-profile`, `~/.local/state/nix`, `~/.config/git`, `~/.config/jj` | :1058-1064 (candidates :967-972) | operator git/jj identity + config readable | low |
| claude config dirs, write-discarding overlay | :1069-1075 | **operator's Claude credentials readable** (RO lower layer) | see T5 |
| `--share-net` | :1080 | **full, unfiltered network egress** | see T5 |
| `--unshare-pid` | :1081 | pid namespace | good |

There is **no `--clearenv`** on the bwrap line. Env hygiene is instead done by prepending `env -i <allowlist>` to the whole invocation (`scrub_env_prefix` :519-530, applied :1455-1456). Allowlist is `PATH`, `HOME`, `TERM` only (`WORKER_ENV_ALLOWLIST` :239). The GitHub token, crosslink state, and `VDD_BWRAP_PIN` are scrubbed from the worker's env. This part is correct: verified that `env -i` wraps the bwrap argv, so the namespace starts from the scrubbed set (:1449-1456).

### 1b. Per-role mount matrix

`MountMatrix::for_role`, `crates/orchestrator/src/spawn.rs:426-459`; `role_gets_jj` :536-538.

| Mount | Implementer | Merger | Adversary | Judge |
|-------|-------------|--------|-----------|-------|
| `<workspace>` RW | yes | yes | yes | yes |
| `<root>/.crosslink/` RO | yes | yes | yes | yes |
| `<root>/.jj/` RW | yes | yes | no | no |
| `<root>/.git/` RW | yes | yes | no | no |
| `<root>/.orchestrator/` | never | never | never | never |

Two consequences, both admitted in-code (`roles/mod.rs:12-43`):

- The Implementer/Merger sandbox binds the **shared repository `.jj/` and `.git/` read-write**. `Write`/`Edit`/`Bash(cargo …)` against those mounts is not contained by any jj-verb allowlist. The tool allowlist is explicitly *not* a cage: "A determined worker can therefore reach and corrupt the VCS store without ever typing a denied `jj` verb" (`roles/mod.rs:21-24`).
- `.crosslink/issues.db` (the **entire** issue tracker DB, all issues + comments) is RO-bound into every worker — a cross-issue confidentiality leak.

### 1c. The orchestrator-side verification path — OUTSIDE the sandbox

This is the sharp edge. After every Implementer commit the pump runs the static QA gate (`pump.rs:692`, and again post-merge `:1397`):

`QaGate::run`, `crates/orchestrator/src/qa.rs:320-341`:
```
Command::new("bash")
    .arg(&script)                 // script = self.workspace.join(".orchestrator/static_qa.sh")  (:294-295)
    .current_dir(&self.workspace) // the worker's RW workspace
    .spawn()
```
- No bwrap. No `env -i`. **No `.env_clear()`.** This inherits the orchestrator's *full* process environment — including `GH_TOKEN`/`GITHUB_TOKEN` when the deployment is in remote-landing mode (read from env at `landing.rs:819-820`).
- `script` is `<workspace>/.orchestrator/static_qa.sh` — a **committed, tracked file inside the worker's RW workspace**. The worker can rewrite it (it is not `<root>/.orchestrator/`, which is what the matrix withholds; it is the tree copy in the worktree, bound RW as part of `<workspace>`).
- The canonical fixture script is `cargo test --locked --offline` (`tests/fixtures/hello/.orchestrator/static_qa.sh`), which compiles and runs worker-authored `build.rs`, proc-macros, and `#[test]` code.

So worker-authored code executes on the **host**, outside any sandbox, with the orchestrator's environment and network. `--offline` does not help: it only blocks cargo's registry fetch, not `build.rs` doing its own I/O.

### 1d. Landing — what actually gates `main`

Local FF landing (`landing.rs:360-394`): `main` is moved only via a fast-forward-guarded bookmark advance — history can only *append*, never rewind (`land_local` / `fast_forward_bookmark`). **This guards history integrity, not content.** There is no orchestrator-side inspection of *what* the change contains; the FF guard would happily fast-forward `main` onto a malicious-but-compiling change. Content review is delegated entirely to the LLM adversary (`roles/adversary.rs`), which reviews a pre-rendered `diff.patch`.

### 1e. Untrusted-input flow (prompt injection surface)

Issue title/description → `task_from_issue` (`implementer.rs:235-238`) → `_orchestrator/task.md` verbatim → both the Implementer's instructions and (via `render_inputs`) the Adversary's review context. The issue body is fully attacker-controlled for inbound/crossbridge issues and reaches two LLMs as instructions.

---

## 2. Threats

### T1 — Malicious QA script / build.rs executes on the host (CRITICAL)
- **Vector:** worker edits `<workspace>/.orchestrator/static_qa.sh`, OR leaves it and adds a `build.rs`/proc-macro/test that `cargo test` runs. QA runs it on the host with full env + network (§1c).
- **Likelihood:** high — this is the *normal* control flow, not an escape. The worker doesn't need a bwrap bug; QA is already outside bwrap.
- **Impact:** total. Arbitrary host code execution as the orchestrator user: read `$GH_TOKEN`, read the operator's Claude creds, pivot to other repos, tamper with `state.db`, exfiltrate, persist. In the 5-server federation this is wormable.
- **Current code vulnerable?** YES. `qa.rs:335-341` spawns bare `bash` on a worker-writable script in the worker's cwd with an inherited environment.
- **Timing:** QA runs *before* adversary review (`pump.rs` implement→QA→adversary), so the adversary never sees the diff before the host-exec has already happened.

### T2 — Malicious code lands and runs on downstream CI / other servers (HIGH)
- **Vector:** code that passes QA + adversary but carries a `build.rs`/test-time payload that fires on the *next* build (this or a federated peer).
- **Likelihood:** medium-high for a crafted adversarial issue.
- **Impact:** high — same host-exec primitive as T1, deferred and propagated.
- **Current code vulnerable?** YES. Landing does no content validation beyond the FF guard (§1d) and one LLM reviewer.

### T3 — Shared `.jj/`/`.git/` corruption (MEDIUM)
- **Vector:** Implementer/Merger writes directly into the RW-bound repository VCS store (`spawn.rs:445-454`) bypassing jj verbs.
- **Likelihood:** medium. **Impact:** medium — corrupts the shared operation log / object store; the S2 per-repo mutex protects concurrency, not malice. The FF guard still prevents `main` rewind, so trunk history survives, but the repo can be DoS'd.
- **Current code vulnerable?** YES, by design admission (`roles/mod.rs:21-24`).

### T4 — Adversary/QA bypass via prompt injection (MEDIUM-HIGH)
- **Vector:** issue body or in-code comments instruct the Adversary LLM to report clean, or instruct the Implementer to embed a payload (§1e).
- **Likelihood:** high for adversarial issues; LLM reviewers are not injection-proof. **Impact:** high — convergence (`N` clean adversary rounds) is the *only* content gate, and it is an LLM. QA is deterministic but only checks "compiles + tests pass", which a payload satisfies.
- **Current code vulnerable?** YES. Convergence trusts the adversary LLM verdict.

### T5 — Credential / Anthropic-creds exfiltration from inside the sandbox (MEDIUM)
- **Vector:** the operator's Claude config/credentials are exposed RO-readable (overlay lower layer, `spawn.rs:1069-1075`) so the worker can authenticate — therefore a malicious worker can *read* those creds, and `--share-net` (`:1080`) lets it POST them anywhere.
- **Likelihood:** medium. **Impact:** medium-high (Anthropic API credential theft).
- **Current code vulnerable?** YES. Note: the write-discarding overlay correctly prevents *tampering* with operator config (finding #3), but not *reading* it. `GH_TOKEN` is NOT reachable here (scrubbed from worker env, §1a) — it is reachable via T1 instead.

### T6 — Host `/etc` disclosure (LOW)
- **Vector:** `--ro-bind /etc /etc` (`:1043`) exposes the entire host `/etc` (any secrets/tokens dropped there, internal hostnames) to every worker.
- **Likelihood:** low-medium. **Impact:** low-medium. **Vulnerable?** YES, but low-value on a NixOS-style host.

### T7 — Bwrap pin bypass (LOW — mitigated)
- The `bwrap` binary is store-path pinned and fail-closed verified before every Claude spawn (`SandboxPin::verify`, `spawn.rs:1417`, :1145-1165). `nix-shell` is pinned-but-unverified, correctly justified: it runs *inside* the already established namespace (`:178-189`). This boundary is sound.

---

## 3. THE SINGLE MOST DANGEROUS GAP

**The static QA gate executes worker-controlled code on the host, outside the sandbox, with the orchestrator's environment and network** (`qa.rs:335-341`, §1c, T1).

The entire bwrap mount matrix, the env scrub, the store-path pin — all of it is bypassed the moment the orchestrator runs `bash <workspace>/.orchestrator/static_qa.sh` (or any `cargo build/test` invoked by it) directly. The worker both *authors the code under test* and *can rewrite the grading script*, and that script runs as the orchestrator user before the adversary ever sees the diff. Every other threat here is secondary to this one: it converts "capable agent in a sandbox" into "arbitrary code execution on the control plane." Unsupervised auto-landing cannot be safe while this is true.

---

## 4. Mitigations (prioritized)

### P0 — Sandbox the verification path (closes T1, blunts T2)
- **`crates/orchestrator/src/qa.rs:335-341`** — run `static_qa.sh` *inside* a bwrap sandbox with the worker mount matrix and `env -i`, exactly like the worker (reuse `SandboxHost::base_mounts` + a matrix; drop `--share-net` for the QA gate — QA should be hermetic, the fixture already assumes `--offline`). Deny host network entirely for QA.
- Run the QA gate under a **dedicated low-privilege UID / ephemeral scratch**, not the orchestrator user, so even a sandbox-escape can't read the control plane.
- Treat `.orchestrator/static_qa.sh` as **orchestrator-owned, not worker-owned**: execute the *trunk* copy from `<root>/.orchestrator/`, not the workspace copy, so a worker cannot rewrite its own grader. (Requires it to move out of the worktree, or a pre-run integrity check against the trunk blob.)

### P1 — Contain the worker sandbox (blunts T5, T6, T2)
- **`spawn.rs:1080`** — replace `--share-net` with an egress-filtered path that reaches *only* the Anthropic API (documented follow-up in `roles/mod.rs:58-62`).
- **Credentials:** issue the worker a **scoped, ephemeral** Anthropic token rather than exposing the operator's config dir RO (`spawn.rs:1069-1075`); today the worker can read and exfiltrate the operator's creds (T5).
- **`spawn.rs:1043`** — narrow `--ro-bind /etc /etc` to the specific files needed (`/etc/resolv.conf`, `/etc/passwd`, `/etc/nix/nix.conf`) instead of all of `/etc`.

### P1 — Isolate the object store (closes T3)
- Give committing roles a **per-worker clone**, not the shared `<root>/.jj`+`.git` RW mount (`spawn.rs:445-454`), and land back under orchestrator control. Removes the direct-corruption primitive the allowlist can't stop.

### P2 — Reduce reliance on LLM review + reduce disclosure (blunts T4)
- Do not treat LLM adversary convergence as the sole content gate for untrusted-origin issues; require human sign-off or a second deterministic gate. Sanitize/label the untrusted issue body before it enters the adversary's context (`implementer.rs:235-238`, adversary `render_inputs`).
- **`spawn.rs:433-437`** — bind a **per-issue view** of crosslink, not the whole `.crosslink/issues.db`, to remove the cross-issue disclosure.

---

## 5. Go / No-Go recommendation

### (a) Trusted-origin issues — CONDITIONAL GO, only after P0
Auto-landing trusted issues still runs machine-generated `build.rs`/test code on the host today (T1/T2). If the pipeline and issue authors are trusted, residual risk is "our own generated code runs on our host," which is tolerable **only once P0 lands** (QA in a network-denied sandbox, grader executed from trunk, non-orchestrator UID). Without P0: **NO-GO** — a single buggy or compromised generation is host RCE.

### (b) Untrusted / inbound (crossbridge) issues — HARD NO-GO
Do not enable unsupervised auto-landing of untrusted issues under the current code. An attacker fully controls the code under test and the QA script, both of which run on the host outside the sandbox (T1), can exfiltrate operator Anthropic creds over unrestricted egress (T5), can corrupt the shared repo (T3), and faces only an injectable LLM as the content gate (T4). This is remotely-triggered arbitrary code execution on the control plane, wormable across the 5-server federation. **P0 + both P1 items + P2 are prerequisites**, and even then untrusted auto-landing warrants a human-in-the-loop checkpoint until the sandboxed pipeline has a track record.

---

## Appendix — key evidence sites
- Base mounts / `--share-net` / no `--clearenv`: `crates/orchestrator/src/spawn.rs:1034-1086`
- Env scrub (`env -i`, allowlist PATH/HOME/TERM): `spawn.rs:239`, `:519-530`, `:1449-1456`
- Per-role mount matrix (.jj/.git RW to committers): `spawn.rs:426-459`, `:536-538`
- Claude creds RO overlay: `spawn.rs:857-869`, `:1069-1075`
- QA host-exec (bare bash, worker script, inherited env): `qa.rs:294-296`, `:320-341`; run sites `pump.rs:692`, `:1397`
- Fixture QA runs cargo: `tests/fixtures/hello/.orchestrator/static_qa.sh`
- GH token from env → octocrab: `landing.rs:819-820`, `:922-923`
- FF-guarded landing (history-only, no content check): `landing.rs:360-394`
- Bwrap store-path pin (sound): `spawn.rs:1417`, `:1145-1165`
- Design's own honesty about the model: `crates/orchestrator/src/roles/mod.rs:12-65`
