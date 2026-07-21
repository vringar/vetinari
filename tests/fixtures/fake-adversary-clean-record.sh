#!/usr/bin/env bash
# A CLEAN fake adversary (like fake-adversary-clean.sh) that ALSO records the
# set of jj workspaces that exist WHILE it runs, so a test can prove the
# Implementer workspace was forgotten BEFORE adversary review (#1 — no orphan
# Implementer workspace can outlive the review window).
#
# It runs with cwd = <root>/.workspace/<adversary-workspace>, so `..` is the
# `.workspace/` directory and `../../.orchestrator/` is the (gitignored)
# orchestrator-private dir — writing the listing there cannot pollute any jj
# change (it is never snapshot into `main`).
#
# Contract: run with the Adversary's prepared workspace as the current directory,
# AFTER the orchestrator has pre-rendered the inputs into `_orchestrator/`.
set -euo pipefail

if [ ! -f _orchestrator/diff.patch ]; then
    echo "fake-adversary-clean-record: missing pre-rendered _orchestrator/diff.patch" >&2
    exit 1
fi

# Record the `.workspace/` directory listing observed during the review. The
# test asserts NO `implementing-*` entry appears here.
ls -1 .. >"../../.orchestrator/adversary-workspaces-seen.txt" 2>/dev/null || true

# --- findings.jsonl: EMPTY (zero bytes) — a clean round with no findings ---
: >_orchestrator/findings.jsonl

# --- result.md: freeform review summary ---
cat >_orchestrator/result.md <<'MD'
Reviewed the pre-rendered diff.patch. No defects — a clean round.
MD

# --- DONE sentinel, written LAST, DECLARING the (empty) findings.jsonl too ---
findings_sha="$(sha256sum _orchestrator/findings.jsonl | cut -d' ' -f1)"
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat >_orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/findings.jsonl","sha256":"$findings_sha"},{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
