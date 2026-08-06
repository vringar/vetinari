#!/usr/bin/env bash
# Deterministic stand-in for a live `claude` Merger worker (REQ-19, L4).
#
# The real Merger runs inside a jj workspace ALREADY checked out in the
# conflicted state: after the orchestrator's rebase of the issue's change onto
# `main` conflicts, the Merger's `src/lib.rs` carries jj conflict markers. Its
# one job is to resolve every marker to a correct merge, then write structured
# artifacts under `_orchestrator/` — ending with the `_orchestrator/DONE`
# sentinel (REQ-3b). This script does exactly that for the `hello` fixture
# conflict with canned output, so the orchestrator's
# conflict → Merger → post-merge-QA → retry-landing loop is testable in CI
# without an Anthropic API call or nondeterministic agent output.
#
# Contract: run with the Merger's prepared jj workspace as the current
# directory, AFTER the orchestrator has pre-rendered `_orchestrator/conflict.md`.
set -euo pipefail

# The Merger reads the pre-rendered conflict context. Fail loudly if the
# orchestrator did not render it, so a broken pre-render surfaces here rather
# than as a silently empty resolution.
if [ ! -f _orchestrator/conflict.md ]; then
    echo "fake-merger: missing pre-rendered _orchestrator/conflict.md" >&2
    exit 1
fi

# Resolve the conflict in `src/lib.rs`. The fixture conflict is between the
# Implementer's appended `say_hi` block and main's appended `MAIN_MARK` const,
# both at end-of-file. A correct merge KEEPS BOTH. We reconstruct the file from
# the shared base (everything before the first conflict marker) plus a clean,
# compiling union of both sides — robust to the header changing.
sed '/^<<<<<<</,$d' src/lib.rs > src/lib.rs.merged
cat >> src/lib.rs.merged <<'RUST'

/// Returns a friendly greeting.
pub fn say_hi() -> &'static str {
    "hello"
}

// conflicting trailing edit on main
pub const MAIN_MARK: u8 = 1;

#[cfg(test)]
mod say_hi_tests {
    use super::say_hi;

    #[test]
    fn greets() {
        assert_eq!(say_hi(), "hello");
    }
}
RUST
mv src/lib.rs.merged src/lib.rs

# Snapshot the resolution into the working-copy commit so the orchestrator (via
# jj_api) reads the resolved, conflict-free tree. Editing out the markers plus
# any jj command clears the conflict; `jj describe` also records the resolution.
jj describe -m "Resolve rebase conflict: merge say_hi with MAIN_MARK"

# --- merge_result.md: freeform "files resolved, strategy used" (REQ-19) ---
cat > _orchestrator/merge_result.md <<'MD'
Resolved the rebase conflict in `src/lib.rs` by keeping both sides: the
Implementer's `say_hi` helper (with its unit test) and main's `MAIN_MARK`
constant. No logic changed; both contributions are preserved.
MD

# --- DONE sentinel, written LAST, listing artifacts by sha256 (REQ-3b) ---
result_sha="$(sha256sum _orchestrator/merge_result.md | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/merge_result.md","sha256":"$result_sha"}]}
JSON
