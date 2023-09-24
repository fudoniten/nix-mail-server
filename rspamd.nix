{ config, lib, pkgs, ... }:

# TODO: use blacklists

with lib;
let
  cfg = config.fudo.mail.rspamd;
  mailCfg = config.fudo.mail;

in {
  options.fudo.mail.rspamd = with types; {
    enable = mkEnableOption "Enable rspamd spam test server.";

    ports = {
      metrics = mkOption {
        type = port;
        default = 7573;
      };
      controller = mkOption {
        type = port;
        default = 11334;
      };
      milter = mkOption {
        type = port;
        default = 11335;
      };
    };

    antivirus = {
      host = mkOption {
        type = str;
        description = "Host of the ClamAV server.";
      };

      port = mkOption {
        type = port;
        description = "Port at which to reach ClamAV";
      };
    };
  };

  config = mkIf cfg.enable {
    services.prometheus.exporters.rspamd = {
      enable = true;
      listenAddress = "127.0.0.1";
      port = cfg.ports.metrics;
    };

    services.rspamd = {
      enable = true;

      locals = {
        "milter_headers.conf".text = "extended_spam_headers = yes;";

        "antivirus.conf".text = ''
          clamav {
            action = "reject";
            symbol = "CLAM_VIRUS";
            type = "clamav";
            log_clean = true;
            servers = "${cfg.antivirus.host}:${toString cfg.antivirus.port}";
            scan_mime_parts = false; # scan mail as a whole unit, not parts. seems to be needed to work at all
          }
        '';

        # "rbl.conf".text = ''
        #   rbls {
        #     an_rbl
        #   }
        # '';
      };

      overrides."milter_headers.conf".text = "extended_spam_headers = true;";

      workers = {
        rspamd_proxy = {
          type = "rspamd_proxy";
          bindSockets = [ "localhost:${toString cfg.ports.milter}" ];
          count = 4;
          extraConfig = ''
            milter = yes;
            timeout = 120s;

            upstream "local" {
              default = yes;
              self_scan = yes;
            }
          '';
        };

        controller = {
          type = "controller";
          count = 4;
          bindSockets = [ "localhost:${toString cfg.ports.controller}" ];
          includes = [ ];
        };
      };
    };
  };
}
