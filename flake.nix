{
  description = "Mail server running in containers.";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.05";
    arion.url = "github:hercules-ci/arion";
  };

  outputs = { self, nixpkgs, arion, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      # Packages for each system
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          mail-monitor = pkgs.callPackage ./package.nix { };
          default = self.packages.${system}.mail-monitor;
        });

      # Apps for each system
      apps = forAllSystems (system: {
        mail-monitor = {
          type = "app";
          program = "${self.packages.${system}.mail-monitor}/bin/mail-monitor";
        };
        default = self.apps.${system}.mail-monitor;
      });

      # NixOS modules
      nixosModules = rec {
        default = mailServerContainer;
        mailServerContainer = { ... }: {
          imports = [ arion.nixosModules.arion ./mail-server.nix ];
        };
        mail-monitor = import ./module.nix;
      };
    };
}
