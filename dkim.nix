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
        opendkim-genkey \
          -s mail \
          -d ${domain} \
          --bits="${toString cfg.key-bits}" \
          --directory=$TMPDIR
        mv $TMPDIR/mail.private ${dkimKey}
        mv $TMPDIR/mail.txt ${dkimTxt}
      fi
    '';

  ensureAllDkimCerts = keyDir: domains:
    concatStringsSep "\n" (map (ensureDomainDkimCert keyDir) domains);

  makeKeyTable = keyDir: domains:
    pkgs.writeText "opendkim-key-table" (concatStringsSep "\n"
      (map (dom: "${dom}:mail:${keyDir}/${dom}.mail.key") domains));

  makeSigningTable = domains:
    pkgs.writeText "opendkim-signing-table"
    (concatStringsSep "\n" (map (dom: "${dom} ${dom}") domains));

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
      selector = cfg.selector;
      domains = let domainString = concatStringsSep "," cfg.domains;
      in "csl:${domainString}";
      configFile = let
        debugString = ''
          Syslog yes
          SyslogSuccess yes
          LogWhy yes
        '';
        keyTable = makeKeyTable cfg.state-directory cfg.domains;
        signingTable = makeSigningTable cfg.domains;
      in pkgs.writeText "opendkim.conf" ''
        Canonicalization relaxed/simple
        Socket inet:${toString cfg.port}
        KeyTable file: ${keyTable}
        SigningTable file:${signingTable}
        ${optionalString cfg.debug debugString}
      '';
    };

    systemd = {
      tmpfiles.rules = let
        user = config.services.opendkim.user;
        group = config.services.opendkim.group;
      in [ "d ${cfg.state-directory} 0700 ${user} ${group} - -" ];
      services.opendkim = {
        serviceConfig = {
          ExecStartPre = pkgs.writeShellScript "ensure-dkim-certs.sh"
            (ensureAllDkimCerts cfg.state-directory cfg.domains);
          ReadWritePaths = [ cfg.state-directory ];
        };
      };
    };
  };
}
