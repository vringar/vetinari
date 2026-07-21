#!/usr/bin/env bash
# Deterministic stand-in for a BROKEN Adversary that wrote a DONE sentinel but
# NEVER produced `_orchestrator/findings.jsonl` — a crashed/incomplete review.
#
# It writes result.md and a DONE that lists ONLY result.md. `DoneSentinel::verify`
# passes (it validates only the artifacts DONE names), so the lenient
# `Findings::read` would map the absent file to "empty ⇒ converged" — the
# false-convergence hole. The strict convergence reader (`Findings::from_done`)
# must REJECT this as an incomplete round (FindingsMissing), never converge.
#
# Contract: run with the Adversary's prepared workspace as the current directory,
# AFTER the orchestrator has pre-rendered the inputs into `_orchestrator/`.
set -euo pipefail

if [ ! -f _orchestrator/diff.patch ]; then
    echo "fake-adversary-no-findings: missing pre-rendered _orchestrator/diff.patch" >&2
    exit 1
fi

# Deliberately DO NOT write _orchestrator/findings.jsonl.

# --- result.md: freeform review summary ---
cat > _orchestrator/result.md <<'MD'
Started reviewing the pre-rendered diff.patch but stopped before writing any
findings — this stands in for a crashed/incomplete Adversary round.
MD

# --- DONE sentinel, written LAST, declaring ONLY result.md (no findings.jsonl) ---
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
