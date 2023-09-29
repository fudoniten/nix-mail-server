{ config, lib, pkgs, ... }:

with lib;
let cfg = config.fudo.mail.dkim;

in {
  options.fudo.mail.dkim = with types; {
    enable = mkEnableOption "Enable DKIM signature verification.";

    debug = mkEnableOption "Enable debug logs.";

    domains = mkOption {
      type = listOf str;
      description =
        "List of domains to be considered local, and signed instead of verified.";
    };

    selector = mkOption {
      type = str;
      description = "Name to use for mail-signing keys.";
      default = "mail";
    };

    port = mkOption {
      type = port;
      description = "Port at which to listen for incoming signing requests.";
      default = 5324;
    };

    state-directory = mkOption {
      type = str;
      description = "Directory at which to store DKIM state (i.e. keys).";
    };
  };

  config = mkIf cfg.enable {
    networking.firewall = {
      enable = true;
      allowedTCPPorts = [ cfg.port ];
    };

    services.opendkim = {
      enable = true;
      selector = cfg.selector;
      socket = "inet:${toString cfg.port}";
      domains = let domainString = concatStringsSep "," cfg.domains;
      in "csl:${domainString}";
      configFile = let
        debugString = ''
          Syslog yes
          SyslogSuccess yes
          LogWhy yes
        '';
      in pkgs.writeText "opendkim.conf" ''
        Canonicalization relaxed/simple
        ${optionalString cfg.debug debugString}
      '';
    };
  };
}
