#!/usr/bin/env bash
# Wires up the blocking relations for the VDD orchestrator issue graph.
# Run this AFTER file_issues.sh has filed all 24 issues.
# ID mapping established by file_issues.sh output:
F1=L1   # Foundation: skeleton
F2=L2   # Foundation: state.db
F3=L3   # Foundation: crosslink_api
F4=L4   # Foundation: jj_api
F5=L5   # Foundation: zellij_host
F6=L6   # Foundation: xtask lint
Z1=L7   # zellij bootstrap
S1=L8   # spawn helper
S2=L9   # workspace lifecycle
S3=L10  # artifact contract
S4=L11  # heartbeat watchdog
S5=L12  # QA gate
S6=L13  # events log
S7=L14  # Implementer role
P1=L15  # build pump
P2=L16  # crash-safe resumption
L2_=L17 # local landing
L4_=L18 # Merger
G1=L19  # close-out test
L3_=L20 # remote landing
A1=L21  # Adversary role
A2=L22  # findings parser
A3=L23  # convergence detector
A4=L24  # iteration 2 E2E

set -euo pipefail

block() {
  # block <blocked-issue> by <blocker-issue>
  crosslink issue block "$1" "$2" 2>&1 | grep -v '^Warning' || true
}

# Foundation depends on F1 (skeleton)
block "$F2" "$F1"
block "$F3" "$F1"
block "$F4" "$F1"
block "$F5" "$F1"
block "$F6" "$F1"

# zellij bootstrap depends on F1 (cargo workspace) + F5 (zellij_host crate)
block "$Z1" "$F1"
block "$Z1" "$F5"

# Spawn helper needs zellij bootstrap, jj_api (for workspace ops invoked nearby), crosslink_api (for sign assertion), F2 (state.db active_workers)
block "$S1" "$Z1"
block "$S1" "$F2"
block "$S1" "$F3"
block "$S1" "$F4"

# Workspace lifecycle needs jj_api + F2 (active_workers)
block "$S2" "$F4"
block "$S2" "$F2"

# Artifact contract needs F2 (posted_artifacts table) + F3 (crosslink_api for posting)
block "$S3" "$F2"
block "$S3" "$F3"

# Heartbeat watchdog needs S1 (spawn produces active_workers rows) + S2 (workspace forget on stale)
block "$S4" "$S1"
block "$S4" "$S2"

# QA gate needs S3 (parses Implementer artifacts) + F3 (post blocker)
block "$S5" "$S3"
block "$S5" "$F3"

# Events log needs F2 (events table mirror)
block "$S6" "$F2"

# Implementer role definition needs S1 (allowlist plumbing)
block "$S7" "$S1"

# Build pump needs S1 (spawn), S2 (workspace), S5 (QA), S6 (events), S7 (Implementer)
block "$P1" "$S1"
block "$P1" "$S2"
block "$P1" "$S5"
block "$P1" "$S6"
block "$P1" "$S7"

# Recovery needs F2 + P1 (pump must exist before recovery makes sense)
block "$P2" "$F2"
block "$P2" "$P1"

# Local landing needs jj_api + F3 (for label transitions)
block "$L2_" "$F4"
block "$L2_" "$F3"
# It also runs only after Implementer reaches converged via the pump
block "$L2_" "$P1"

# Merger needs S1 + S5 (post-merge QA gate) + L2 (the failing rebase path)
block "$L4_" "$S1"
block "$L4_" "$S5"
block "$L4_" "$L2_"

# Close-out test needs the whole MVP loop: pump, recovery, local landing, merger
block "$G1" "$P1"
block "$G1" "$P2"
block "$G1" "$L2_"
block "$G1" "$L4_"
# Also the lint must be passing so CI-style verification works:
block "$G1" "$F6"

# Remote landing comes after close-out
block "$L3_" "$G1"

# Adversary track all depends on close-out passing
block "$A1" "$G1"
block "$A1" "$S1"     # uses spawn
block "$A1" "$F4"     # uses jj_api for diff pre-rendering

block "$A2" "$A1"
block "$A2" "$S3"     # extends artifact parser
block "$A2" "$F2"     # uses posted_artifacts

block "$A3" "$A2"     # convergence reads findings
block "$A3" "$F2"     # last_diff_hash + empty_round_streak

block "$A4" "$A3"

echo "Block graph wired."
