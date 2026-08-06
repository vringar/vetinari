#!/usr/bin/env bash
# A fake Merger that FAILS to resolve the conflict (REQ-19 failure path, AC-14).
#
# It writes a valid `_orchestrator/DONE` sentinel but leaves the conflict markers
# in `src/lib.rs` untouched (makes no edit, snapshots nothing), so the working-
# copy commit stays conflicted. The orchestrator does NOT trust the worker's
# self-reported exit status — it inspects the merged tree itself — so its
# post-merge conflict check must catch the unresolved conflict and park the issue
# at `phase:awaiting-human-merge`. This exercises the "Merger failed → park"
# path without an Anthropic API call.
#
# Contract: run with the Merger's prepared jj workspace as the current directory,
# AFTER the orchestrator has pre-rendered `_orchestrator/conflict.md`.
set -euo pipefail

if [ ! -f _orchestrator/conflict.md ]; then
    echo "fake-merger-unresolved: missing pre-rendered _orchestrator/conflict.md" >&2
    exit 1
fi

# Deliberately do NOT resolve: leave src/lib.rs with its conflict markers.

# --- merge_result.md + DONE (still written, to prove the orchestrator's OWN
#     tree check — not the worker's self-report — is what parks the issue) ---
cat > _orchestrator/merge_result.md <<'MD'
Unable to resolve the rebase conflict (deliberate test fixture: conflict markers
left in place).
MD
result_sha="$(sha256sum _orchestrator/merge_result.md | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/merge_result.md","sha256":"$result_sha"}]}
JSON
