{ config, lib, pkgs, ... }:

# ClamAV Antivirus Scanner Module
#
# Provides virus and malware scanning for incoming and outgoing email.
# Integrates with Rspamd via TCP socket for real-time scanning.
#
# Key features:
# - Automatic virus database updates via freshclam
# - TCP socket interface for integration with mail filters
# - Phishing URL scanning disabled (handled by Rspamd instead)
#
# Architecture choice: Phishing detection is delegated to Rspamd which has
# more sophisticated URL analysis and reputation checking capabilities.

with lib;
let cfg = config.fudo.mail.clamav;

in {
  options.fudo.mail.clamav = with types; {
    enable = mkEnableOption "Enable virus scanning with ClamAV.";

    state-directory = mkOption {
      type = str;
      description = "Path at which to store ClamAV database.";
      default = "/var/lib/clamav";
    };

    port = mkOption {
      type = port;
      description = "Port on which to listen for incoming requests.";
      default = 15407;
    };
  };

  config = mkIf cfg.enable {
    # Create dedicated clamav user and group for daemon isolation
    # Uses standard NixOS IDs for consistency across deployments
    users = {
      users.clamav = {
        isSystemUser = true;
        uid = config.ids.uids.clamav;
        home = mkForce cfg.state-directory;
        description = "ClamAV daemon user";
        group = "clamav";
      };
      groups.clamav = {
        members = [ "clamav" ];
        gid = config.ids.gids.clamav;
      };
    };

    # Ensure state directory exists with correct permissions
    # 0750 = owner rwx, group r-x, others none
    systemd.tmpfiles.rules =
      [ "d ${cfg.state-directory} 0750 clamav clamav - -" ];

    services.clamav = {
      daemon = {
        enable = true;
        settings = {
          # Phishing detection disabled - handled by Rspamd which has
          # better URL reputation and analysis capabilities
          PhishingScanURLs = "no";

          # Custom database location for easier backups and management
          DatabaseDirectory = mkForce cfg.state-directory;

          # Run as dedicated clamav user for security isolation
          User = mkForce "clamav";

          # TCP socket for integration with Rspamd
          # Unix sockets would be more secure but harder to containerize
          TCPSocket = cfg.port;
        };
      };

      # Automatic virus database updates via freshclam
      updater = {
        enable = true;
        settings = {
          DatabaseDirectory = mkForce cfg.state-directory;
          DatabaseOwner = "clamav";
        };
      };
    };
  };
}
