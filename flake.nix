{
  description = "Mail server running in containers.";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.11";
    arion.url = "github:hercules-ci/arion";
  };

  outputs = { self, nixpkgs, arion, ... }:
    let
      # Overlay to build vectorscan with SSSE3-only baseline for older CPUs
      # The fat runtime bundles multiple implementations and selects at runtime
      # based on CPU capabilities. This version excludes AVX2/AVX512 to ensure
      # compatibility with older hardware that only has SSSE3 support.
      #
      # Background: Hyperscan/vectorscan requires at minimum SSSE3 (not SSE4.2).
      # The standard nixpkgs build enables AVX2/AVX512 which can cause issues
      # on older CPUs. By building with only the baseline SSSE3 implementation,
      # we ensure rspamd works on older hardware while still benefiting from
      # vectorscan's regex acceleration.
      legacyCpuOverlay = final: prev: {
        vectorscan = prev.vectorscan.overrideAttrs (oldAttrs: {
          cmakeFlags = [
            (if oldAttrs.enableShared or true then
              "-DBUILD_SHARED_LIBS=ON"
            else
              "-DBUILD_STATIC_LIBS=ON")
            # Fat runtime with only baseline SSSE3 support
            # No AVX2/AVX512 to avoid issues on older CPUs
            "-DFAT_RUNTIME=ON"
            "-DBUILD_AVX2=OFF"
            "-DBUILD_AVX512=OFF"
            "-DBUILD_AVX512VBMI=OFF"
          ];
        });
      };
    in {
      # Expose the overlay for users who want to apply it to their own nixpkgs
      overlays.default = legacyCpuOverlay;

      nixosModules = rec {
        default = mailServerContainer;
        mailServerContainer = { ... }: {
          imports = [ arion.nixosModules.arion ./mail-server.nix ];
          nixpkgs.overlays = [ legacyCpuOverlay ];
        };
      };
    };
}
