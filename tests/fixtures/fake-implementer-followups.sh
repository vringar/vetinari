#!/usr/bin/env bash
# Fake Implementer that ALSO proposes follow-up work (REQ-SWARM-2, spec §1.6).
#
# Identical to `fake-implementer.sh` (implements `say_hi`, commits, writes
# result.md + DONE), but additionally drops `_orchestrator/followups.jsonl` with
# two proposals and lists it in DONE. It exercises the propose-don't-commit
# channel end to end: the orchestrator must translate these into `--kind note`
# comments and apply the `followup:proposed` label — and NOTHING else
# (no new issue, no `phase:*`, no blocker edge). The worker has read-only
# tracker access and never writes the graph itself.
#
# Contract: run with the worker's jj workspace as the current directory.
set -euo pipefail

if [ -n "$(jj diff --name-only)" ]; then
    echo "fake-implementer-followups: refusing to run on a non-empty change (@ is dirty):" >&2
    jj diff --name-only >&2
    exit 1
fi

mkdir -p _orchestrator

# --- implement: append `say_hi` and its test to the crate (fmt-clean) ---
cat >> src/lib.rs <<'RUST'

/// Returns a friendly greeting.
pub fn say_hi() -> &'static str {
    "hello"
}

#[cfg(test)]
mod say_hi_tests {
    use super::say_hi;

    #[test]
    fn greets() {
        assert_eq!(say_hi(), "hello");
    }
}
RUST

jj describe -m "Add say_hi helper with a passing test"

cat > _orchestrator/result.md <<'MD'
Added `say_hi() -> &'static str` returning `"hello"`, plus a unit test. While
here I noticed follow-up work, proposed separately.
MD

# --- follow-up PROPOSALS (one JSON object per line). PROPOSALS, not commits:
#     a human/chief reviews and may later graph them. suggested_blockers is
#     advisory text only — never a wired edge. ---
cat > _orchestrator/followups.jsonl <<'JSONL'
{"title":"Add a say_bye() farewell helper","rationale":"Symmetry with say_hi; several callers will want a matching farewell.","suggested_blockers":[1],"gate_sketch":"unit test asserting say_bye() == \"bye\""}
{"title":"Localize greetings","rationale":"Greetings are hard-coded English; a locale param would generalize them.","suggested_blockers":[]}
JSONL

# --- DONE sentinel, LAST, listing BOTH artifacts by sha256 (REQ-3b) ---
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
followups_sha="$(sha256sum _orchestrator/followups.jsonl | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/result.md","sha256":"$result_sha"},{"path":"_orchestrator/followups.jsonl","sha256":"$followups_sha"}]}
JSON
