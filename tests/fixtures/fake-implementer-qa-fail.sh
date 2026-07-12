#!/usr/bin/env bash
# A deterministic Implementer stand-in that ALWAYS produces a change failing the
# static QA gate — used to prove the QA-fail → re-spawn retry loop is LIVE and
# bounded (it re-drives from state.db each round and poisons after
# MAX_QA_RETRIES). See tests/dogfood variants.
#
# It writes a real, non-empty change (so the empty-commit guard passes and QA is
# actually reached), commits it via `jj describe`, and ends with the DONE
# sentinel — exactly like the happy-path fake, except the code does not compile,
# so `cargo test` (the fixture's static_qa.sh) fails every round.
set -euo pipefail

if [ -n "$(jj diff --name-only)" ]; then
    echo "fake-implementer-qa-fail: refusing to run on a non-empty change:" >&2
    jj diff --name-only >&2
    exit 1
fi

mkdir -p _orchestrator

# --- implement: append code that does NOT compile (QA `cargo test` will fail) ---
cat >> src/lib.rs <<'RUST'

/// Intentionally broken: references an undefined symbol so `cargo test` fails.
pub fn broken() -> &'static str {
    this_symbol_does_not_exist()
}
RUST

jj describe -m "Add broken() that fails to compile"

cat > _orchestrator/result.md <<'MD'
Added a `broken()` helper. (Fixture: this intentionally fails static QA.)
MD

result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
