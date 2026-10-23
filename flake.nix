{
  description = "Logos keystore module — scrypt vaults, BIP39/BIP32 HD derivation, secp256k1 signing (offline, no network).";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # logos.wallets/1 (wallets.lidl): the signer manager, bound at runtime, since it depends on
    # this module and this module can't depend on it.
    logos-signer-interface = {
      url = "github:logos-co/logos-signer-interface/ca091a9330d455a5b60b80537e34dc535d1e6503";
      flake = false;
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems f;

      # x86_64-windows is a cross PSEUDO-SYSTEM the builder already understands
      # (logos-module-builder lib/common.nix routes it to
      # logos-nix.lib.mkWindowsPkgs, and picks the build platform separately).
      # It is a target, never a host we evaluate nixpkgs natively for, so it
      # only ever belongs in `packages`.
      targets = systems ++ [ "x86_64-windows" ];
      forAllTargets = f: nixpkgs.lib.genAttrs targets f;
      unitTests = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "keystore-unit-tests";
        version = "1.0.0";
        src = pkgs.runCommand "keystore-test-src" { } ''
          mkdir -p $out
          cp -r ${./rust-lib} $out/rust-lib
          cp -r ${logos-module-builder.packages.${pkgs.stdenv.hostPlatform.system}.rust-sdk-src} $out/logos-rust-sdk-src
        '';
        sourceRoot = "keystore-test-src/rust-lib";
        cargoLock = { lockFile = ./rust-lib/Cargo.lock; allowBuiltinFetchGit = true; };
        buildNoDefaultFeatures = true;
        doCheck = true;
      };
    in
    {
      packages = forAllTargets (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system} // nixpkgs.lib.optionalAttrs (builtins.elem system systems) {
          unit-tests = unitTests (import nixpkgs { inherit system; });
        });
      checks = forAllSystems (system: { unit-tests = self.packages.${system}.unit-tests; });
    };
}
