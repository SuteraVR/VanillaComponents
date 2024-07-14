{
  description = "Sutera developing environment of Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, rust-overlay, crane, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        rust-beta = pkgs.rust-bin.beta.latest.default;
        rust-nightly = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default);

        craneLib = crane.mkLib pkgs;

        commonArgs = { source, rust }: {
          src = craneLib.cleanCargoSource source;
          strictDeps = true;

          nativeBuildInputs = [
            pkgs.libiconv
            rust
          ];
        };

        gateway-stable-args = commonArgs { source = ./gateway; inherit rust; };
        gateway-stable = craneLib.buildPackage (gateway-stable-args // {
          cargoArtifacts = craneLib.buildDepsOnly gateway-stable-args;
        });
      in {
        packages = {
          inherit gateway-stable;
        };

        devShells = {
          default = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.libiconv
              rust
            ];
            shellHook = ''
              exec $SHELL
            '';
          };

          beta = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.libiconv
              rust-beta
            ];
            shellHook = ''
              exec $SHELL
            '';
          };

          nightly = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.libiconv
              rust-nightly
            ];
            shellHook = ''
              exec $SHELL
            '';
          };
        };
      }
    );
}
