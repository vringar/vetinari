# Nix entry point exposing the crosslink that vetinari builds against, so other
# configurations (e.g. a NixOS config) can use exactly the same crosslink.
# The single source of truth is the `crosslink` pin in npins/sources.json;
# bump it with `npins update crosslink`.
{
  sources ? import ./npins,
  pkgs ? import sources.nixpkgs {},
}: rec {
  # Pinned crosslink source tree (repo root; the crate lives in ./crosslink).
  crosslink-src = sources.crosslink;
  # Exact pinned revision.
  crosslink-rev = sources.crosslink.revision;
  # crosslink CLI built from the pinned source. The dashboard is not built
  # (crosslink embeds a placeholder page), matching `just bootstrap`.
  crosslink = pkgs.rustPlatform.buildRustPackage {
    pname = "crosslink";
    version = "git-${builtins.substring 0 8 crosslink-rev}";
    src = crosslink-src;
    sourceRoot = "source/crosslink";
    cargoLock.lockFile = "${crosslink-src}/crosslink/Cargo.lock";
    nativeBuildInputs = [pkgs.pkg-config];
    buildInputs = [pkgs.openssl];
    # rust-embed needs dashboard/dist to exist at compile time.
    preBuild = ''
      chmod -R u+w ..
      mkdir -p ../dashboard/dist
      echo '<!doctype html><title>crosslink dashboard placeholder</title>' > ../dashboard/dist/index.html
    '';
    doCheck = false;
    meta.mainProgram = "crosslink";
  };
}
