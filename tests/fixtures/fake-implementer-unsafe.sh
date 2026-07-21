#!/usr/bin/env bash
# Content-driven fake Implementer for the AC-15 iteration-2 end-to-end test
# (A4, #24). Unlike fake-implementer.sh (which always writes the same say_hi
# change), this worker's OUTPUT depends on whether a prior Adversary finding
# flagged the seeded flaw — so the flawed → fixed transition is driven by real
# review content, not a scripted round counter.
#
# The AC-15 scenario: the Implementer's FIRST commit produces code with a
# deliberate flaw — an `unsafe { }` block that calls `get_unchecked` behind a
# safe-looking API. It compiles and its test passes, so it clears the QA gate and
# reaches the Adversary. When a prior round flagged the flaw, the re-implement
# round writes the FIXED variant (safe, bounds-checked indexing — no unsafe, no
# get_unchecked).
#
# Cross-round signal (REQ-8 findings threading): the ORCHESTRATOR delivers the
# accumulated prior findings into THIS worker's own workspace at
# `_orchestrator/prior_findings.jsonl` before the spawn (see the pump's
# `render_prior_findings`). It is empty on the first round and carries the
# Adversary's finding on the re-implement round. This is the same channel a real
# Direct/generalized worker reads — there is no fixture-to-fixture side channel.
#
# Contract: run with the worker's jj workspace as the current directory.
set -euo pipefail

# Guard: the worker must start from a fresh, empty change (see fake-implementer.sh).
# `_orchestrator/` is gitignored, so the orchestrator-delivered prior findings do
# not count as a dirty change.
if [ -n "$(jj diff --name-only)" ]; then
    echo "fake-implementer-unsafe: refusing to run on a non-empty change (@ is dirty):" >&2
    jj diff --name-only >&2
    exit 1
fi

mkdir -p _orchestrator

# The orchestrator-delivered prior findings for this round (REQ-8). Non-empty ⇒
# a prior Adversary finding must be addressed ⇒ write the FIXED variant.
prior="_orchestrator/prior_findings.jsonl"

if [ -s "$prior" ]; then
    # A prior Adversary finding was delivered: write the FIXED variant (safe,
    # bounds-checked indexing — no unsafe block, no get_unchecked).
    cat >>src/lib.rs <<'RUST'

/// Returns the first byte of the canonical greeting.
pub fn greeting_head() -> u8 {
    let bytes = b"hello";
    // Safe, bounds-checked indexing — addresses the adversary's blocker.
    bytes[0]
}

#[cfg(test)]
mod greeting_head_tests {
    use super::greeting_head;

    #[test]
    fn head_is_h() {
        assert_eq!(greeting_head(), b'h');
    }
}
RUST
    msg="Reimplement greeting_head with safe indexing"
    summary="Re-implemented greeting_head with safe, bounds-checked indexing, removing the unsafe block the adversary flagged."
else
    # No prior finding: write the FLAWED variant — the AC-15 seeded flaw, an
    # `unsafe { }` block whose distinctive marker is the `get_unchecked` call. It
    # compiles and the test passes (so QA is green); only a reviewer objects to
    # the unchecked index.
    cat >>src/lib.rs <<'RUST'

/// Returns the first byte of the canonical greeting.
pub fn greeting_head() -> u8 {
    let bytes = b"hello";
    // AC-15 seeded flaw: an `unsafe { }` block calling `get_unchecked`. It
    // compiles and the test below passes; only a reviewer objects that the
    // unchecked index has no justification a safe bounds check couldn't give.
    unsafe { *bytes.get_unchecked(0) }
}

#[cfg(test)]
mod greeting_head_tests {
    use super::greeting_head;

    #[test]
    fn head_is_h() {
        assert_eq!(greeting_head(), b'h');
    }
}
RUST
    msg="Add greeting_head helper"
    summary="Added greeting_head returning the first byte of the greeting. No prior findings to address."
fi

# --- commit the change (the Implementer owns the jj describe) ---
jj describe -m "$msg"

# --- result artifact: freeform, becomes the PR body in remote mode ---
cat >_orchestrator/result.md <<MD
$summary
MD

# --- DONE sentinel, written LAST, listing artifacts by sha256 (REQ-3b) ---
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat >_orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
