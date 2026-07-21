# Dev shell for the AC-11b self-dogfood target (a shell.nix-bearing real-cargo
# repo the orchestrator lands a change onto).
#
# `build_target_fixture()` (crates/orchestrator/tests/common/mod.rs) copies this
# file to the target repo's `shell.nix` and copies this repo's `npins/` beside
# it, so a live `claude` Implementer entering `nix-shell <workspace>/shell.nix`
# inside its bwrap sandbox gets the SAME pinned Rust toolchain + jujutsu this
# repo uses (REQ-1, "reuse this repo's toolchain"). It is deliberately leaner
# than the repo's own shell.nix: no `just bootstrap` shellHook, no JJ_SRC /
# CROSSLINK_SRC (the target crate has zero dependencies, so no jj-lib patch is
# needed), so it evaluates and enters cleanly inside the worker namespace.
{
  sources ? import ./npins,
  pkgs ?
    import sources.nixpkgs {
      overlays = [(import sources.rust-overlay)];
    },
}: let
  rustToolchain = pkgs.rust-bin.stable.latest.default;
in
  pkgs.mkShell {
    name = "ac11b-target";
    packages = [
      rustToolchain
      pkgs.jujutsu
    ];
  }
