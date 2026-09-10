{
  description = "Mail server running in containers.";

  inputs = {
    # 26.05, not 25.11. dovecot.nix and postfix.nix are written against
    # the 26.05 module rewrite -- services.dovecot2.settings,
    # includeFiles, settings.default_internal_user, and
    # services.dovecot2.package, which in 25.11 is an explicitly REMOVED
    # option. None of them evaluate on the branch this used to name.
    #
    # The mismatch was invisible because nothing referenced this input:
    # the modules take `pkgs` from whoever imports them, so the declared
    # pin governed nothing. It still documents the supported baseline,
    # and the `follows` below makes it load-bearing.
    nixpkgs.url = "nixpkgs/nixos-26.05";

    arion = {
      url = "github:hercules-ci/arion";
      # One nixpkgs in the lock instead of two. Inert for how this flake
      # uses arion -- its NixOS module builds the arion package from the
      # importing host's `pkgs`, not from this input -- so this only
      # stops a second full nixpkgs being fetched and locked.
      inputs.nixpkgs.follows = "nixpkgs";
    };
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
