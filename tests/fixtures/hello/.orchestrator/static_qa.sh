#!/usr/bin/env bash
# Static QA gate for the hello fixture (REQ-9 / AC-11a).
#
# The orchestrator runs this after every Implementer commit; a non-zero exit is
# a blocker fed back to the next Implementer round. It is deliberately minimal
# but real — `cargo test` compiles the crate and runs its tests, so it gates
# both "does it build" and "do the tests pass". The richer fmt/clippy template
# lives in the design doc (REQ-9a); this fixture keeps QA deterministic for the
# happy-path dogfood.
#
# `--locked --offline` keeps the gate hermetic: the crate has zero dependencies
# and a committed `Cargo.lock`, so QA never reaches the network or mutates the
# lockfile — a QA run must not itself dirty the working copy.
set -euo pipefail
cargo test --locked --offline --quiet
