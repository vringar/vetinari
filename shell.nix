# vetinari dev shell — classic nixpkgs invocation, dependencies pinned via npins.
#
# Enter with `nix-shell` (or direnv). The orchestrator enters this same file to
# run each worker's `claude` inside a direct `bwrap` sandbox.
# Sources are pinned in npins/sources.json; bump with `npins update`.
#
# The orchestrator drives `bwrap` DIRECTLY to enforce the per-role worker mount
# matrix (REQ-5/6/7), so `bwrap` is the pinned isolation binary: the shellHook
# below exports its resolved store-hash as VDD_BWRAP_PIN (plus the dev-shell
# launcher as VDD_NIX_SHELL_PIN), and the spawn guard refuses to run a worker
# unless the `bwrap` on PATH resolves to exactly VDD_BWRAP_PIN (AC-19, REQ-4a).
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
      # Source tree of the npins-pinned crosslink (forecast-bio/crosslink,
      # `develop`). `just bootstrap` symlinks this to `.crosslink-src` so the
      # `crosslink_api` insulation crate can path-depend on the `crosslink`
      # library crate (REQ-1, REQ-3a). Bump with `npins update crosslink`.
      CROSSLINK_SRC = "${sources.crosslink}";
    };

    # `bwrap` and `nix-shell` are resolved at shell-entry time so the realpath
    # captures the exact pinned store build. The orchestrator's spawn helper
    # reads VDD_BWRAP_PIN and refuses to spawn a worker if the resolved `bwrap`
    # drifts (VDD_NIX_SHELL_PIN is used to enter the dev shell by absolute path).
    shellHook = ''
      if command -v bwrap >/dev/null 2>&1; then
        export VDD_BWRAP_PIN="$(readlink -f "$(command -v bwrap)")"
      else
        echo "WARNING: bwrap (bubblewrap) not on PATH — the orchestrator cannot sandbox workers." >&2
        export VDD_BWRAP_PIN=""
      fi
      if command -v nix-shell >/dev/null 2>&1; then
        # Resolve to the store bin dir but KEEP the `nix-shell` basename: with
        # lix/nix the `nix-shell` entry is a symlink to the multiplexed `nix`
        # binary, and a plain `readlink -f` would collapse it to `.../bin/nix`.
        # Invoked as `nix` (argv[0]) that binary parses `nix <shell.nix> --run`
        # as a `nix` subcommand, NOT as `nix-shell`, so the worker's dev-shell
        # entry breaks. Preserving the basename keeps argv[0] = `nix-shell`.
        export VDD_NIX_SHELL_PIN="$(dirname "$(readlink -f "$(command -v nix-shell)")")/nix-shell"
      else
        export VDD_NIX_SHELL_PIN=""
      fi
      echo "vetinari dev shell — rustc $(rustc --version | cut -d' ' -f2), jj $(jj --version | cut -d' ' -f2), zellij $(zellij --version | cut -d' ' -f2)"
      [ -n "''${VDD_BWRAP_PIN:-}" ] && echo "bwrap pinned at: $VDD_BWRAP_PIN"
      # Keep .cargo/config.toml's jj-lib patch in sync with the pinned jj
      # source so a bare `cargo build` (no `just`) resolves correctly.
      if command -v just >/dev/null 2>&1 && [ -f justfile ]; then
        just bootstrap || echo "WARNING: just bootstrap failed — run it manually before building." >&2
      fi
      echo "next: just build  (or  just lint)"
    '';
  }
