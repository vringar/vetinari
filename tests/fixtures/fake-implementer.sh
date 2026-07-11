#!/usr/bin/env bash
# Deterministic stand-in for a live `claude` Implementer worker.
#
# The real Implementer (REQ-5) runs inside a jj workspace, edits the crate,
# commits its change with `jj describe`, and writes structured artifacts under
# `_orchestrator/` — ending with the `_orchestrator/DONE` sentinel (REQ-3b).
# This script does exactly that for the `hello` fixture with canned output, so
# the orchestrator's spawn -> QA -> land loop is testable in CI without an
# Anthropic API call or nondeterministic agent output.
#
# Contract: run with the worker's jj workspace as the current directory.
set -euo pipefail

# Guard: the worker must start from a fresh, empty change. Editing on top of an
# already-dirty `@` would fold unrelated files into the Implementer's commit and
# then onto `main` (REQ-17). Fail loudly rather than silently pollute.
if [ -n "$(jj diff --name-only)" ]; then
    echo "fake-implementer: refusing to run on a non-empty change (@ is dirty):" >&2
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

# --- commit the change (the Implementer owns the jj describe) ---
jj describe -m "Add say_hi helper with a passing test"

# --- result artifact: freeform, becomes the PR body in remote mode ---
cat > _orchestrator/result.md <<'MD'
Added `say_hi() -> &'static str` returning `"hello"`, plus a unit test asserting
the greeting. No prior findings to address.
MD

# --- DONE sentinel, written LAST, listing artifacts by sha256 (REQ-3b) ---
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
