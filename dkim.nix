{ config, lib, pkgs, ... }:

with lib;
let
  cfg = config.fudo.mail.dkim;

  ensureDomainDkimCert = keyDir: domain:
    let
      dkimKey = "${keyDir}/${domain}.mail.key";
      dkimTxt = "${keyDir}/${domain}.mail.txt";
    in ''
      if [ ! -f "${dkimKey}" ] || [ ! -f ${dkimTxt} ]; then
        OUT=$(${pkgs.coreutils}/bin/mktemp -d -t dkim-XXXXXXXXXX)
        opendkim-genkey \
          --selector=mail \
          --domain=${domain} \
          --bits="${toString cfg.key-bits}" \
          --directory=$OUT
        mv $OUT/mail.private ${dkimKey}
        mv $OUT/mail.txt ${dkimTxt}
      fi
    '';

  ensureAllDkimCerts = keyDir: domains:
    concatStringsSep "\n" (map (ensureDomainDkimCert keyDir) domains);

  makeKeyTable = keyDir: domains:
    pkgs.writeTextDir "key.table" (concatStrings (map (dom: ''
      ${dom} ${dom}:mail:${keyDir}/${dom}.mail.key
    '') domains));

  makeSigningTable = domains:
    pkgs.writeTextDir "signing.table" (concatStrings (map (dom: ''
      ${dom} ${dom}
    '') domains));

  keyTableDir = makeKeyTable cfg.state-directory cfg.domains;
  signingTableDir = makeSigningTable cfg.domains;

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

    key-bits = mkOption {
      type = int;
      description = ''
        How many bits in generated DKIM keys. RFC6376 advises minimum 1024-bit keys.

        If you have already deployed a key with a different number of bits than specified
        here, then you should use a different selector (dkimSelector). In order to get
        this package to generate a key with the new number of bits, you will either have to
        change the selector or delete the old key file.
      '';
      default = 2048;
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
      allowedUDPPorts = [ cfg.port ];
    };

    services.opendkim = {
      enable = true;
      selector = cfg.selector;
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
        Socket inet:${toString cfg.port}
        KeyTable file:${keyTableDir}/key.table
        SigningTable file:${signingTableDir}/signing.table
        ${optionalString cfg.debug debugString}
      '';
    };

    systemd = {
      tmpfiles.rules = let
        user = config.services.opendkim.user;
        group = config.services.opendkim.group;
      in [ "d ${cfg.state-directory} 0700 ${user} ${group} - -" ];
      services.opendkim = {
        path = with pkgs; [ opendkim ];
        serviceConfig = {
          ExecStartPre = [
            (pkgs.writeShellScript "ensure-dkim-certs.sh"
              (ensureAllDkimCerts cfg.state-directory cfg.domains))
          ];
          ReadWritePaths = [ cfg.state-directory ];
          ReadOnlyPaths = [ keyTableDir signingTableDir ];
        };
      };
    };
  };
}
