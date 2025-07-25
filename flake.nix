{
  description = "Mail server running in containers.";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.05";
    arion.url = "github:hercules-ci/arion";
  };

  outputs = { self, nixpkgs, arion, ... }: {
    nixosModules = rec {
      default = mailServerContainer;
      mailServerContainer = { ... }: {
        imports = [ arion.nixosModules.arion ./mail-server.nix ];
      };
    };
  };
}
