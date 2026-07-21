#!/usr/bin/env bash
# Deterministic stand-in for a live `claude` Adversary that flags a finding on
# the FIRST review of a change, then signs off once the change has been
# re-implemented to address it — driving the pump's re-implement-on-findings
# cycle (A2, #22).
#
# It keys its verdict off the orchestrator-rendered `_orchestrator/prior_findings.json`
# (REQ-8): the orchestrator accumulates each round's findings and renders them as
# the next Adversary round's prior findings. So:
#   - round 0 (prior_findings == []) → flag ONE finding derived from the diff,
#   - round 1+ (prior findings present) → a CLEAN round (empty findings.jsonl),
#     i.e. "the re-implemented change now addresses the prior finding".
# This proves both directions: findings → re-implement, and that prior findings
# actually reach the next Adversary round.
#
# Contract: run with the Adversary's prepared workspace as the current directory,
# AFTER the orchestrator has pre-rendered the inputs into `_orchestrator/`.
set -euo pipefail

if [ ! -f _orchestrator/diff.patch ]; then
    echo "fake-adversary-flag: missing pre-rendered _orchestrator/diff.patch" >&2
    exit 1
fi

# The orchestrator ALWAYS renders prior_findings.json (a JSON array; `[]` on the
# first round). Whitespace-strip it so `[]` compares cleanly.
prior="$(tr -d '[:space:]' < _orchestrator/prior_findings.json 2>/dev/null || echo '[]')"

if [ "$prior" = "[]" ] || [ -z "$prior" ]; then
    # Round 0: flag one finding, citing the file the pre-rendered diff touched
    # (proves the worker consumed its input).
    touched="$(grep -m1 '^+++ b/' _orchestrator/diff.patch | sed 's#^+++ b/##')"
    : "${touched:=src/lib.rs}"
    cat > _orchestrator/findings.jsonl <<JSONL
{"severity":"high","location":"$touched:1","claim":"say_hi has no test covering the empty-string boundary","evidence_files":["$touched"]}
JSONL
else
    # Re-review after re-implementation: prior findings are present, so the
    # change now addresses them — a CLEAN round (empty findings.jsonl).
    : > _orchestrator/findings.jsonl
fi

# --- result.md: freeform review summary ---
cat > _orchestrator/result.md <<'MD'
Adversary review of the pre-rendered diff.patch against the task and any prior
findings.
MD

# --- DONE sentinel, written LAST, DECLARING both artifacts (REQ-3b) ---
findings_sha="$(sha256sum _orchestrator/findings.jsonl | cut -d' ' -f1)"
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/findings.jsonl","sha256":"$findings_sha"},{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
