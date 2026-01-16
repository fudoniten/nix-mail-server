{ config, lib, pkgs, ... }:

# DKIM (DomainKeys Identified Mail) Signing Module
#
# Provides cryptographic email signing for outbound messages and verification
# for inbound messages. DKIM helps receiving servers verify that emails
# actually came from your domain and weren't tampered with in transit.
#
# Key features:
# - Automatic signing of outbound mail for local domains
# - Verification of DKIM signatures on inbound mail
# - Per-domain key management with configurable selector
# - Integration with Postfix via milter protocol
#
# Architecture choice: Uses OpenDKIM for mature, well-tested DKIM implementation.
# Keys are stored in state-directory and should be backed up securely.
#
# Note: After key generation, you must publish the public key as a TXT record
# in DNS at: <selector>._domainkey.<domain>

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
    services.opendkim = {
      enable = true;

      # Selector identifies which key to use for signing
      # Published in DNS as <selector>._domainkey.<domain>
      selector = cfg.selector;

      # TCP socket for integration with Postfix milter interface
      # Format: "inet:<port>@<host>" (host defaults to localhost)
      socket = "inet:${toString cfg.port}";

      # Comma-separated list of local domains to sign (not verify)
      # Format: "csl:domain1,domain2,..."
      # Mail FROM these domains gets signed, all others get verified
      domains = let domainString = concatStringsSep "," cfg.domains;
      in "csl:${domainString}";

      configFile = let
        debugString = ''
          Syslog yes
          SyslogSuccess yes
          LogWhy yes
        '';
      in pkgs.writeText "opendkim.conf" ''
        # Canonicalization: relaxed/simple
        # - relaxed header: allows insignificant whitespace changes
        # - simple body: body must not change at all
        # This is a good balance between compatibility and security
        Canonicalization relaxed/simple
        ${optionalString cfg.debug debugString}
      '';
    };
  };
}
