#!/usr/bin/env bash
# Deterministic stand-in for a live `claude` Adversary that drives the A3
# streak-RESET path: it is CLEAN on its first review (the streak climbs to 1),
# FLAGS a finding on its second review (mid-streak — the orchestrator must reset
# empty_round_streak to 0 and re-implement), then CLEAN forever after. With
# `[convergence] n_rounds = 2` the issue must therefore need TWO fresh clean
# rounds AFTER the reset before it converges — proving a mid-streak finding
# restarts the consecutive-clean count from scratch (REQ-10, A3).
#
# The verdict is driven by a persisted call counter under the orchestrator-
# private `.orchestrator/` dir (never snapshot into any jj change), because a
# clean adversary re-review does NOT bump the round and the pre-rendered
# `prior_findings.json` is constant within one change's review loop — so round
# number and prior findings cannot distinguish the calls; an external counter can.
#
# Call sequence (n is the 0-based call index):
#   n = 0 → CLEAN   (streak → 1)
#   n = 1 → FLAG    (finding → reset streak to 0, re-implement)
#   n >= 2 → CLEAN  (the re-implemented change signs off; streak climbs 1, 2 → converge)
#
# Contract: run with the Adversary's prepared workspace as the current directory,
# AFTER the orchestrator has pre-rendered the inputs into `_orchestrator/`. cwd is
# `<root>/.workspace/<adversary-workspace>`, so `../../.orchestrator/` is the repo's
# gitignored orchestrator-private dir.
set -euo pipefail

if [ ! -f _orchestrator/diff.patch ]; then
    echo "fake-adversary-flag-midstreak: missing pre-rendered _orchestrator/diff.patch" >&2
    exit 1
fi

counter_file="../../.orchestrator/flaky-counter.txt"
n="$(cat "$counter_file" 2>/dev/null || echo 0)"
case "$n" in
    ''|*[!0-9]*) n=0 ;;
esac
echo "$((n + 1))" >"$counter_file"

if [ "$n" -eq 1 ]; then
    # Second call: flag ONE finding mid-streak, citing the file the diff touched.
    touched="$(grep -m1 '^+++ b/' _orchestrator/diff.patch | sed 's#^+++ b/##')"
    : "${touched:=src/lib.rs}"
    cat >_orchestrator/findings.jsonl <<JSONL
{"severity":"high","location":"$touched:1","claim":"say_hi drops a mid-streak regression the first review missed","evidence_files":["$touched"]}
JSONL
else
    # Every other call: a clean round (empty, DONE-attested findings).
    : >_orchestrator/findings.jsonl
fi

# --- result.md: freeform review summary ---
cat >_orchestrator/result.md <<'MD'
Adversary review of the pre-rendered diff.patch (mid-streak flake fixture).
MD

# --- DONE sentinel, written LAST, DECLARING both artifacts (REQ-3b) ---
findings_sha="$(sha256sum _orchestrator/findings.jsonl | cut -d' ' -f1)"
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat >_orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/findings.jsonl","sha256":"$findings_sha"},{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
