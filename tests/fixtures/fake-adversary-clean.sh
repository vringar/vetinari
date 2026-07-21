#!/usr/bin/env bash
# Deterministic stand-in for a live `claude` Adversary that found NOTHING — a
# clean/converged round (REQ-10). It writes an EMPTY `_orchestrator/findings.jsonl`
# (zero bytes), a result.md, and a DONE sentinel that DECLARES both artifacts.
#
# This is the valid convergence signal: an explicitly-present, DONE-attested but
# empty findings file. The strict reader (`Findings::from_done`) must accept it
# as a clean round (zero findings), distinct from a crashed Adversary that never
# wrote findings.jsonl at all (see fake-adversary-no-findings.sh).
#
# Contract: run with the Adversary's prepared workspace as the current directory,
# AFTER the orchestrator has pre-rendered the inputs into `_orchestrator/`.
set -euo pipefail

if [ ! -f _orchestrator/diff.patch ]; then
    echo "fake-adversary-clean: missing pre-rendered _orchestrator/diff.patch" >&2
    exit 1
fi

# --- findings.jsonl: EMPTY (zero bytes) — a clean round with no findings ---
: > _orchestrator/findings.jsonl

# --- result.md: freeform review summary ---
cat > _orchestrator/result.md <<'MD'
Reviewed the pre-rendered diff.patch and log.txt. No correctness, safety, or
missed-requirement defects found — a clean round.
MD

# --- DONE sentinel, written LAST, DECLARING the (empty) findings.jsonl too ---
findings_sha="$(sha256sum _orchestrator/findings.jsonl | cut -d' ' -f1)"
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/findings.jsonl","sha256":"$findings_sha"},{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
