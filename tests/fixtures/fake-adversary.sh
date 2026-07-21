#!/usr/bin/env bash
# Deterministic stand-in for a live `claude` Adversary worker.
#
# The real Adversary (REQ-8) reviews an Implementer's change with fresh context
# and NO `.jj/` mount: it reads pre-rendered inputs under `_orchestrator/`
# (`diff.patch`, `log.txt`, `prior_findings.json`, `task.md`), tries to refute
# the change, and writes each finding as one JSON line to
# `_orchestrator/findings.jsonl` — ending with the `_orchestrator/DONE` sentinel
# (REQ-3b). This script does exactly that with canned output, so the
# orchestrator's Adversary spawn -> parse round-trip is testable in CI without an
# Anthropic API call or nondeterministic agent output.
#
# Contract: run with the Adversary's prepared workspace as the current directory,
# AFTER the orchestrator has pre-rendered the inputs into `_orchestrator/`.
set -euo pipefail

# The Adversary reads the pre-rendered diff — it never runs `jj diff`. Fail
# loudly if the orchestrator did not render it, so a broken pre-render surfaces
# here rather than as a silently empty review.
if [ ! -f _orchestrator/diff.patch ]; then
    echo "fake-adversary: missing pre-rendered _orchestrator/diff.patch" >&2
    exit 1
fi

# Derive one canned finding FROM the pre-rendered diff, proving the worker
# actually consumed its input: cite the file the change touched.
touched="$(grep -m1 '^+++ b/' _orchestrator/diff.patch | sed 's#^+++ b/##')"
: "${touched:=src/lib.rs}"

# --- findings.jsonl: one JSON finding per line (the Adversary output) ---
cat > _orchestrator/findings.jsonl <<JSONL
{"severity":"med","location":"$touched:1","claim":"say_hi has no doc example demonstrating the returned greeting","evidence_files":["$touched"]}
JSONL

# --- result.md: freeform review summary ---
cat > _orchestrator/result.md <<'MD'
Reviewed the pre-rendered diff.patch and log.txt. One medium finding: the new
helper lacks a doc example. No correctness or safety defects found.
MD

# --- DONE sentinel, written LAST, listing artifacts by sha256 (REQ-3b) ---
findings_sha="$(sha256sum _orchestrator/findings.jsonl | cut -d' ' -f1)"
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/findings.jsonl","sha256":"$findings_sha"},{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
