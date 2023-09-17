{ config, lib, pkgs, ... }:

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

    systemd.tmpfiles.rules =
      [ "d ${cfg.state-directory} 0750 clamav clamav - -" ];

    services.clamav = {
      enable = true;
      settings = {
        PhishingScanURLs = "no";
        DatabaseDirectory = mkForce cfg.state-directory;
        User = "clavmav";
        TCPSocket = cfg.port;
      };
    };
    updater = {
      enable = true;
      settings = {
        DatabaseDirectory = mkForce cfg.state-directory;
        DatabaseOwner = "clamav";
      };
    };
  };
}
