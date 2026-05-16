# vetinari dev shell — classic nixpkgs invocation, dependencies pinned via npins.
#
# Enter with `nix-shell` (or direnv). `claude-sandbox` auto-detects this file.
# Sources are pinned in npins/sources.json; bump with `npins update`.
#
# `claude-sandbox` is NOT provided here. Install it via your nix profile and the
# orchestrator pins the expected store-hash at runtime via VDD_CLAUDE_SANDBOX_PIN
# (set by shellHook below). The version-mismatch assertion (AC-19) lands in
# crosslink issue #8 (S1).
{
  sources ? import ./npins,
  pkgs ?
    import sources.nixpkgs {
      overlays = [(import sources.rust-overlay)];
    },
}: let
  # Pinned Rust toolchain. The toolchain version follows the pinned
  # rust-overlay; bump it with `npins update rust-overlay`.
  rustToolchain = pkgs.rust-bin.stable.latest.default.override {
    extensions = ["rust-src" "rust-analyzer" "clippy" "rustfmt"];
  };
in
  pkgs.mkShell {
    name = "vetinari-dev";

    packages = [
      rustToolchain
      pkgs.cargo-nextest
      pkgs.cargo-watch
      pkgs.just
      pkgs.jujutsu
      pkgs.sqlite
      pkgs.python3
      pkgs.zellij
      pkgs.bubblewrap
      pkgs.pkg-config
      pkgs.openssl
      pkgs.git
      pkgs.gh
      pkgs.alejandra
    ];

    env = {
      RUST_BACKTRACE = "1";
      # Source tree of the pinned jujutsu package. `just bootstrap` reads this
      # to generate `.cargo/config.toml`, redirecting the `jj-lib` crates.io
      # dependency to `$JJ_SRC/lib` so the orchestrator links the *exact* same
      # jj version the workers drive via the `jj` CLI (REQ-1, REQ-1c).
      JJ_SRC = "${pkgs.jujutsu.src}";
    };

    # `claude-sandbox` is resolved at shell-entry time so the realpath captures
    # the user's currently-installed version. The orchestrator's spawn helper
    # reads VDD_CLAUDE_SANDBOX_PIN and refuses to spawn if the resolved path
    # drifts.
    shellHook = ''
      if command -v claude-sandbox >/dev/null 2>&1; then
        export VDD_CLAUDE_SANDBOX_PIN="$(readlink -f "$(command -v claude-sandbox)")"
      else
        echo "WARNING: claude-sandbox not on PATH — install it (e.g. via your nix profile) before running the orchestrator." >&2
        export VDD_CLAUDE_SANDBOX_PIN=""
      fi
      echo "vetinari dev shell — rustc $(rustc --version | cut -d' ' -f2), jj $(jj --version | cut -d' ' -f2), zellij $(zellij --version | cut -d' ' -f2)"
      [ -n "''${VDD_CLAUDE_SANDBOX_PIN:-}" ] && echo "claude-sandbox pinned at: $VDD_CLAUDE_SANDBOX_PIN"
      # Keep .cargo/config.toml's jj-lib patch in sync with the pinned jj
      # source so a bare `cargo build` (no `just`) resolves correctly.
      if command -v just >/dev/null 2>&1 && [ -f justfile ]; then
        just bootstrap || echo "WARNING: just bootstrap failed — run it manually before building." >&2
      fi
      echo "next: just build  (or  just lint)"
    '';
  }
