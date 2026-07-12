#!/usr/bin/env bash
# A deterministic Implementer stand-in that writes a VALID DONE sentinel but
# makes NO change to the tree (never edits a file, never `jj describe`s a
# non-empty change). Used to prove the empty-commit landing guard (#4): the pump
# must refuse to fast-forward `main` onto an empty commit and must NOT report the
# issue Merged.
set -euo pipefail

if [ -n "$(jj diff --name-only)" ]; then
    echo "fake-implementer-empty: refusing to run on a non-empty change:" >&2
    jj diff --name-only >&2
    exit 1
fi

mkdir -p _orchestrator

# --- NO edits to the crate, NO jj describe: @ stays an empty change == main. ---

cat > _orchestrator/result.md <<'MD'
Did nothing. (Fixture: exercises the empty-commit landing guard.)
MD

# --- DONE sentinel, written LAST (REQ-3b) — a valid, successful sentinel. ---
result_sha="$(sha256sum _orchestrator/result.md | cut -d' ' -f1)"
cat > _orchestrator/DONE <<JSON
{"exit_status":"success","artifacts":[{"path":"_orchestrator/result.md","sha256":"$result_sha"}]}
JSON
