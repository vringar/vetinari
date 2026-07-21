#!/usr/bin/env bash
# Content-driven fake Adversary for the AC-15 iteration-2 end-to-end test
# (A4, #24). Unlike fake-adversary-flag.sh (which keys its verdict off the
# orchestrator-rendered `prior_findings.json`, i.e. a round proxy), this worker's
# verdict is driven by the ACTUAL change content: it FLAGS a finding if and only
# if the pre-rendered `_orchestrator/diff.patch` still contains the seeded flaw's
# distinctive marker — a `get_unchecked` call — and signs off CLEAN once the
# re-implemented change has removed it. This closes the adversarial loop honestly:
# the verdict follows the real diff, not a scripted counter, and the marker is a
# specific code token (not the word "unsafe"), so an incidental mention of
# "unsafe" in a comment or the FIXED variant can never re-flag a clean change.
#
# The finding it records reaches the next Implementer round through the
# ORCHESTRATOR: the pump translates it to a `--kind blocker`, accumulates it, and
# delivers it into the next Implementer's workspace (REQ-8). This worker writes
# only its own `_orchestrator/` outputs — no fixture-to-fixture side channel.
#
# Contract: run with the Adversary's prepared workspace as the current directory,
# AFTER the orchestrator has pre-rendered the inputs into `_orchestrator/`.
set -euo pipefail

if [ ! -f _orchestrator/diff.patch ]; then
    echo "fake-adversary-unsafe: missing pre-rendered _orchestrator/diff.patch" >&2
    exit 1
fi

if grep -q 'get_unchecked' _orchestrator/diff.patch; then
    # The change under review still carries the seeded flaw (get_unchecked) — FLAG
    # it, citing the file the pre-rendered diff touched (proves the worker consumed
    # its input). The claim still names the unsafe block for the reader.
    touched="$(grep -m1 '^+++ b/' _orchestrator/diff.patch | sed 's#^+++ b/##')"
    : "${touched:=src/lib.rs}"
    finding='{"severity":"high","location":"'"$touched"':1","claim":"greeting_head hides an unsafe { } block (get_unchecked) behind a safe-looking API; the unchecked index is unjustified","evidence_files":["'"$touched"'"]}'
    printf '%s\n' "$finding" >_orchestrator/findings.jsonl
else
    # No get_unchecked remains — a CLEAN round (empty, DONE-attested findings).
    : >_orchestrator/findings.jsonl
fi

# --- result.md: freeform review summary ---
cat >_orchestrator/result.md <<'MD'
Adversary review of the pre-rendered diff.patch. The verdict is driven by the
actual change content: an unsafe { } block calling get_unchecked behind a
safe-looking API is a blocker; its absence is a clean round.
MD

# --- DONE sentinel, written LAST, DECLARING both artifacts (REQ-3b) ---
findings_sha="$(sha256sum _orchestrator/findings.jsonl | cut -d' ' -f1)"
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat >_orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/findings.jsonl","sha256":"$findings_sha"},{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
