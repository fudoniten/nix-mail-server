{ config, lib, pkgs, ... }@toplevel:

# Mail Server Orchestration Module
#
# This is the main module that orchestrates all mail server components using
# Arion for container-based deployment. It provides a complete, production-ready
# email infrastructure with modern security and spam protection.
#
# ARCHITECTURE OVERVIEW:
#
# Container Structure:
# ├── postfix       - SMTP server (send/receive email)
# ├── dovecot       - IMAP/LMTP server (store/access email)
# ├── rspamd        - Spam/virus filtering
# ├── opendkim      - DKIM email signing
# ├── clamav        - Antivirus scanning
# └── redis         - Statistics and learning backend
#
# Network Topology:
# - external-network: Internet-facing services (Postfix SMTP, Dovecot IMAP)
# - internal-network: Inter-service communication
# - redis-network: Redis backend access
# - ldap-network: LDAP authentication (via Authentik)
#
# Data Flow:
# 1. Incoming mail: Internet -> Postfix (25) -> Rspamd -> DKIM verify -> Dovecot (LMTP)
# 2. Outgoing mail: Client -> Postfix (587/465) -> SASL auth -> Rspamd -> DKIM sign -> Internet
# 3. Mail access: Client -> Dovecot (143/993) -> LDAP auth -> Maildir storage
# 4. Spam learning: User actions -> Sieve scripts -> Rspamd -> Redis (Bayes update)
#
# Key Features:
# - Multi-domain support with virtual mailboxes
# - LDAP authentication via Authentik
# - Comprehensive spam filtering (Rspamd + ClamAV)
# - Email signing and verification (DKIM)
# - Auto-learning spam detection (Bayes)
# - Full-text search (Xapian)
# - Prometheus metrics for all services
# - Container isolation for security
#
# Security Model:
# - Each service runs in isolated container with minimal capabilities
# - Secrets requiring external coordination (LDAP bind password, Authentik
#   outpost token) come from a runtime secrets store, read at start-up.
#   Internal-only secrets (Dovecot's admin password, the Redis password
#   this module and rspamd.nix share) still default to a value derived
#   from build-seed and embedded in the Nix store, but can be pointed at a
#   runtime secrets store too via the internal-secrets.*-file options.
# - TLS required for all client connections (submission/IMAP)
# - SASL authentication via LDAP
# - Multi-layer spam/abuse prevention
# - Regular virus database updates

with lib;
let
  cfg = config.fudo.mail;

  # Three internal-only secrets: nothing outside this module (and, for the
  # Redis password, rspamd.nix) ever needs to agree on their value, so
  # unlike the LDAP secrets above they default to one generated
  # deterministically from build-seed rather than requiring a caller to
  # supply one. Each internal-secrets.*-file option lets a caller point at
  # a runtime secrets store instead; when it does, that path is what gets
  # `cat`'d below, in place of the build-seed-derived store path. Either
  # way the *value* is only ever read at start-up now, never baked into
  # one of the generated config files at eval time -- a Nix store path is
  # just as readable by `cat` at boot as a runtime-only one is, so there's
  # no reason for the two cases to take different code paths.
  dovecotAdminPasswdPath = toString
    (if cfg.internal-secrets.dovecot-admin-password-file != null then
      cfg.internal-secrets.dovecot-admin-password-file
    else
      pkgs.lib.passwd.stablerandom-passwd-file "dovecot-admin-passwd"
      config.instance.build-seed);

  dovecotApiKeyPath = toString
    (if cfg.internal-secrets.dovecot-api-key-file != null then
      cfg.internal-secrets.dovecot-api-key-file
    else
      pkgs.lib.passwd.stablerandom-passwd-file "dovecot-api-key"
      config.instance.build-seed);

  redisPasswdPath = toString (if cfg.internal-secrets.redis-password-file
    != null then
    cfg.internal-secrets.redis-password-file
  else
    pkgs.lib.passwd.stablerandom-passwd-file "mail-server-redis-passwd"
    config.instance.build-seed);

  # Runtime paths for the four files below, shared between the assembly
  # script and the arion container mounts that read them -- so the path
  # is written once rather than duplicated at every use site.
  ldapProxyEnvPath = "/run/mail-server/ldap-proxy/env";
  dovecotLdapConfigPath = "/run/mail-server/dovecot-secrets/ldap.conf";
  dovecotAdminConfigPath = "/run/mail-server/dovecot-secrets/admin.conf";
  postfixLdapRecipientsPath =
    "/run/mail-server/postfix-secrets/ldap-recipients.cf";

  # These four files each need a secret inline, and until now got it via
  # `pkgs.writeText` + `readFile cfg.ldap.bind-password-file` (or
  # `dovecotAdminPasswdPath`/`dovecotApiKeyPath`) -- which resolves the
  # value at EVAL TIME. That's fine for a value the Nix store can hold in
  # the clear, but `bind-password-file` (and, when set, `outpost-token-file`
  # or an internal-secrets.*-file) exist specifically to let the value come
  # from a runtime secrets store (Aegis) that only populates the path after
  # boot -- nothing exists at the path when this expression evaluates, so
  # `readFile` threw, or on a host rebuilding itself with a stale file
  # already sitting in /run from a previous boot, silently reused whatever
  # secret happened to already be there. Assembling these at start-up
  # instead, from the actual runtime paths, is what makes them work the way
  # the "-file" options advertise.
  #
  # jq isn't used here the way the Matrix module uses it for its JWT
  # fragment: these are Dovecot/Postfix config file formats, not JSON, so
  # plain shell heredocs do the substitution instead. Nothing interpolated
  # from Nix here is secret -- authentik-host, bind-dn, base, etc. are
  # ordinary config -- only the `$(cat ...)`-read shell variables are.
  assembleMailSecrets = pkgs.writeShellScript "mail-secrets-assembly" ''
    set -euo pipefail
    umask 077

    ${if cfg.ldap.outpost-token-file != null then ''
      TOKEN="$(cat ${escapeShellArg cfg.ldap.outpost-token-file})"
    '' else ''
      TOKEN=${escapeShellArg cfg.ldap.outpost-token}
    ''}
    BIND_PW="$(cat ${escapeShellArg cfg.ldap.bind-password-file})"
    ADMIN_PW="$(cat ${escapeShellArg dovecotAdminPasswdPath})"
    ${optionalString (cfg.imap.api-port != null) ''
      API_KEY="$(cat ${escapeShellArg dovecotApiKeyPath})"
    ''}

    install -d -m 0755 "$(dirname ${escapeShellArg ldapProxyEnvPath})"
    install -d -m 0755 "$(dirname ${escapeShellArg dovecotLdapConfigPath})"
    install -d -m 0755 \
      "$(dirname ${escapeShellArg postfixLdapRecipientsPath})"

    # World-readable to match the containers' expectations: they run as
    # in-container UIDs with no fixed relationship to the host, the same
    # reason the tmpfiles rules these replace copied everything 0644.
    cat > ${escapeShellArg ldapProxyEnvPath} <<EOF
    AUTHENTIK_HOST=${cfg.ldap.authentik-host}
    AUTHENTIK_TOKEN=$TOKEN
    AUTHENTIK_INSECURE=false
    EOF
    chmod 0644 ${escapeShellArg ldapProxyEnvPath}

    cat > ${escapeShellArg dovecotLdapConfigPath} <<EOF
    uris = ldap://ldap-proxy:3389
    ldap_version = 3
    dn = ${cfg.ldap.bind-dn}
    dnpass = $BIND_PW
    auth_bind = yes
    auth_bind_userdn = cn=%n,${cfg.ldap.user-ou},${cfg.ldap.base}
    base = ${cfg.ldap.base}
    user_filter = (&(objectClass=organizationalPerson)(cn=%n))
    pass_filter = (&(objectClass=organizationalPerson)(cn=%n))
    pass_attrs = =user=%{ldap:cn}
    user_attrs = =user=%{ldap:cn}
    EOF
    chmod 0644 ${escapeShellArg dovecotLdapConfigPath}

    cat > ${escapeShellArg postfixLdapRecipientsPath} <<EOF
    server_host = ldap-proxy
    server_port = 3389
    version = 3
    bind = yes
    bind_dn = ${cfg.ldap.bind-dn}
    bind_pw = $BIND_PW
    search_base = ${cfg.ldap.user-ou},${cfg.ldap.base}
    scope = sub
    query_filter = (&(objectClass=organizationalPerson)(cn=%u))
    result_attribute = cn
    result_format = OK
    EOF
    chmod 0644 ${escapeShellArg postfixLdapRecipientsPath}

    cat > ${escapeShellArg dovecotAdminConfigPath} <<EOF
    doveadm_password = $ADMIN_PW
    ${optionalString (cfg.imap.api-port != null)
      "doveadm_api_key = \$API_KEY"}
    EOF
    chmod 0644 ${escapeShellArg dovecotAdminConfigPath}
    '';

in {
  options.fudo.mail = with types; {
    enable = mkEnableOption "Enable mail server.";

    debug = mkEnableOption "Enable verbose logging.";

    state-directory = mkOption {
      type = str;
      description = "Directory at which to store server state.";
    };

    mail-user = mkOption {
      type = str;
      description = "User as which to store mail.";
      default = "fudo-mail";
    };

    mail-group = mkOption {
      type = str;
      description = "Group as which to store mail.";
      default = "fudo-mail";
    };

    primary-domain = mkOption {
      type = str;
      description = "Primary domain name served by this server.";
    };

    extra-domains = mkOption {
      type = listOf str;
      description = "List of additional domains served by this server.";
      default = [ ];
    };

    admin-email = mkOption {
      type = str;
      description = "Email of mail server administrator.";
      default = "admin@${toplevel.config.fudo.mail.primary-domain}";
    };

    message-size-limit = mkOption {
      type = int;
      description = "Max allowed size of messages, in megabytes.";
      default = 100;
    };

    sasl-domain = mkOption {
      type = str;
      description = "SASL domain to use for authentication.";
    };

    quota = {
      enable = mkEnableOption "Enable user quotas for email storage.";

      limit = mkOption {
        type = str;
        description = "Default quota limit per user (e.g., '10G', '1000M').";
        default = "10G";
      };

      exemptions = mkOption {
        type = listOf str;
        description = "List of usernames exempt from quota limits.";
        default = [ ];
        example = [ "admin" ];
      };
    };

    blacklist = {
      senders = mkOption {
        type = listOf str;
        description =
          "List of email addresses for which we will never send email.";
        default = [ ];
      };

      recipients = mkOption {
        type = listOf str;
        description =
          "List of email addresses for which we will not accept email.";
        default = [ ];
      };

      dns = mkOption {
        type = listOf str;
        description = "List of DNS spam blacklists to use.";
        default = [ ];
      };
    };

    aliases = {
      user-aliases = mkOption {
        type = attrsOf (listOf str);
        description =
          "Map of username to list of aliases mapping to that user.";
        default = { };
      };

      alias-users = mkOption {
        type = attrsOf (listOf str);
        description =
          "Map of alias user to list of users who should receive email.";
        default = { };
      };
    };

    metrics-port = mkOption {
      type = port;
      description = "Port on which to serve metrics.";
      default = 5034;
    };

    antispam = {
      hyperscan = mkOption {
        type = bool;
        default = true;
        description = ''
          Build rspamd with hyperscan (vectorscan) regex acceleration.

          Vectorscan's x86_64 baseline needs SSE4.2 + POPCNT, so on a
          pre-Nehalem CPU (a Core 2-era Xeon, say) rspamd built with it
          dies with SIGILL. Set this false on such hardware: rspamd falls
          back to PCRE matching, slower but functional. Passed through to
          fudo.mail.rspamd.hyperscan inside the antispam container.
        '';
      };
    };

    trusted-networks = mkOption {
      type = listOf str;
      description = "List of networks to be considered trusted.";
      default = [ ];
    };

    fail2ban = {
      enable = mkEnableOption "Enable fail2ban for brute force protection.";

      bantime = mkOption {
        type = int;
        description = "Ban duration in seconds.";
        default = 3600; # 1 hour
      };

      maxretry = mkOption {
        type = int;
        description = "Number of failures before banning.";
        default = 5;
      };

      findtime = mkOption {
        type = int;
        description = "Time window in seconds to count failures.";
        default = 600; # 10 minutes
      };
    };

    ldap = {
      authentik-host = mkOption {
        type = str;
        description = "Hostname of the LDAP outpost provider.";
        default = "authentik.${toplevel.config.fudo.mail.primary-domain}";
      };

      outpost-token = mkOption {
        type = nullOr str;
        description = ''
          Token with which to authenticate to the Authentik host, as a
          literal value baked into the Nix store at build time.

          Mutually exclusive with outpost-token-file: set that one instead
          when the token comes from a runtime secrets store (Aegis, etc.)
          that only populates its target path after boot, rather than
          something safe to embed in the store.
        '';
        default = null;
      };

      outpost-token-file = mkOption {
        type = nullOr str;
        description = ''
          Path to a file containing the Authentik outpost token, read at
          service start-up rather than embedded in the Nix store. Use this
          instead of outpost-token when the file is populated at runtime
          by something other than this module (Aegis, etc.) -- it need not
          exist at build time.

          Mutually exclusive with outpost-token.
        '';
        default = null;
      };

      bind-dn = mkOption {
        type = str;
        description = "DN as which to bind with the LDAP server.";
      };

      bind-password-file = mkOption {
        type = str;
        description = ''
          File containing password with which to bind with the LDAP
          server, read at service start-up. Need not exist at build time
          -- this is what lets it be a secret delivered at boot (Aegis,
          etc.) rather than one baked into the Nix store.
        '';
      };

      base = mkOption {
        type = str;
        description = "Base of the LDAP server.";
        example = "dc=fudo,dc=org";
      };

      user-ou = mkOption {
        type = str;
        description = "Organizational unit containing users.";
        default = "ou=users";
      };

      group-ou = mkOption {
        type = str;
        description = "Organizational unit containing users.";
        default = "ou=groups";
      };
    };

    internal-secrets = {
      dovecot-admin-password-file = mkOption {
        type = nullOr str;
        default = null;
        description = ''
          Runtime path to Dovecot's doveadm admin password, read at
          start-up. Nothing outside this module needs to agree on this
          value, so when left null (the default) one is generated
          deterministically from build-seed instead -- fine for a value
          nothing external reads, but not a real secret at rest. Set this
          to use a real secrets store (Aegis, etc.) instead.
        '';
      };

      dovecot-api-key-file = mkOption {
        type = nullOr str;
        default = null;
        description = ''
          Same as dovecot-admin-password-file, for doveadm's HTTP API key.
          Only read when imap.api-port is set.
        '';
      };

      redis-password-file = mkOption {
        type = nullOr str;
        default = null;
        description = ''
          Runtime path to the password securing this mail server's
          internal Redis instance (shared by rspamd's statistics/fuzzy-hash
          storage and Dovecot), read at start-up. Left null by default for
          the same reason as dovecot-admin-password-file.
        '';
      };
    };

    images = {
      ldap-proxy = mkOption {
        type = str;
        description = "Docker image to use for LDAP proxy.";
        default = "ghcr.io/goauthentik/ldap:latest";
      };
    };

    smtp = {
      hostname = mkOption {
        type = str;
        description =
          "Hostname to use for the SMTP server. Must resolve to this host.";
        default = "smtp.${config.fudo.mail.primary-domain}";
      };

      ssl-directory = mkOption {
        type = str;
        description =
          "Directory containing SSL certificates for SMTP hostname.";
      };

      spf.enable = mkOption {
        type = bool;
        description =
          "Enable Sender Policy Framework checking on incoming messages.";
        default = true;
      };
    };

    imap = {
      hostname = mkOption {
        type = str;
        description =
          "Hostname to use for the IMAP server. Must resolve to this host.";
        default = "imap.${config.fudo.mail.primary-domain}";
      };

      ssl-directory = mkOption {
        type = str;
        description =
          "Directory containing SSL certificates for IMAP hostname.";
      };

      api-port = mkOption {
        type = nullOr port;
        description = "Port to open for Dovecot HTTP admin API.";
        default = null;
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [{
      assertion = (cfg.ldap.outpost-token == null)
        != (cfg.ldap.outpost-token-file == null);
      message = ''
        fudo.mail.ldap: set exactly one of outpost-token (a literal value)
        or outpost-token-file (a runtime path) -- not both, or neither.
        Setting both would leave it ambiguous which one actually reaches
        the LDAP proxy; setting neither leaves it with no token at all.
      '';
    }];

    # mailLdapProxyEnv, dovecotLdapConfig, postfixLdapRecipients,
    # dovecotAdminConfig and redisPasswd all used to live here (or, for
    # redisPasswd, get bind-mounted from a build-seed-derived store path
    # directly), the first four built via `pkgs.writeText` + `readFile` --
    # which resolves the secret at EVAL TIME, baking it into the Nix store.
    # `assembleMailSecrets` (systemd service below) replaces the composed
    # ones, assembling the same files at start-up instead, from whatever
    # `bind-password-file`, `outpost-token-file` and the internal-secrets
    # options point at when the service actually runs. redisPasswd needs no
    # such assembly -- it's a bare value, not a composed file -- so it's
    # just bind-mounted straight from `redisPasswdPath` into the containers
    # that need it, below.
    networking.firewall = { allowedTCPPorts = [ 25 143 465 587 993 ]; };

    systemd.tmpfiles.rules = [
      "d ${cfg.state-directory}/dovecot            0700 - - - -"
      "d ${cfg.state-directory}/dovecot-dhparams   0700 - - - -"
      "d ${cfg.state-directory}/antivirus          0700 - - - -"
      "d ${cfg.state-directory}/dkim               0700 - - - -"
      "d ${cfg.state-directory}/mail               0700 - - - -"
      # Both of these were relying on the container runtime auto-creating
      # the bind-mount source; declared here instead so ownership and mode
      # are deterministic. Root-owned like the rest -- the containers chown
      # their own mountpoints (systemd StateDirectory= for redis,
      # postfix-setup for postfix), the same way the mail directory works.
      "d ${cfg.state-directory}/redis              0700 - - - -"
      "d ${cfg.state-directory}/postfix            0700 - - - -"
      # Secret directories for container mounts. assembleMailSecrets
      # writes directly to these -- nothing left here needs a "C+" copy
      # rule the way the legacy host-secrets pipeline used.
      "d /run/mail-server                          0755 - - - -"
      "d /run/mail-server/ldap-proxy               0755 - - - -"
      "d /run/mail-server/dovecot-secrets          0755 - - - -"
      "d /run/mail-server/postfix-secrets          0755 - - - -"
    ];

    # Ordered `before`/`requiredBy` the arion project's own unit rather than
    # the other way around, so this works regardless of what else orders
    # against arion-mail-server -- the same reasoning matrix-module's
    # matrix-jwt-config uses for its own boot-time secret assembly.
    # Deliberately no ConditionPathExists on any secret path: a skipped
    # unit counts as satisfied, so the containers would start anyway and
    # fail on a missing/empty config file with a far less obvious error.
    #
    # `after = [ "aegis-secrets.target" ]` and not `requires`: this module
    # has no idea whether the host it's running on uses Aegis at all, and
    # ordering after a target that doesn't exist is a harmless no-op, while
    # requiring one would turn "Aegis isn't in use here" into a hard
    # failure.
    systemd.services.mail-secrets = {
      description = "Assemble the mail server's composed runtime secrets.";
      wantedBy = [ "multi-user.target" ];
      before = [ "arion-mail-server.service" ];
      requiredBy = [ "arion-mail-server.service" ];
      after = [ "aegis-secrets.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = assembleMailSecrets;
      };
    };

    # Fail2ban configuration for brute force protection
    services.fail2ban = mkIf cfg.fail2ban.enable {
      enable = true;
      maxretry = cfg.fail2ban.maxretry;
      bantime = "${toString cfg.fail2ban.bantime}";

      jails = {
        # Postfix SMTP authentication failures
        postfix-sasl.settings = {
          enabled = true;
          filter = "postfix-sasl";
          port = "smtp,submission,submissions";
          logpath = "/var/log/journal";
          backend = "systemd";
          findtime = "${toString cfg.fail2ban.findtime}";
        };

        # Dovecot IMAP/POP3 authentication failures
        dovecot.settings = {
          enabled = true;
          filter = "dovecot";
          port = "imap,imaps,pop3,pop3s";
          logpath = "/var/log/journal";
          backend = "systemd";
          findtime = "${toString cfg.fail2ban.findtime}";
        };
      };
    };

    virtualisation.arion.projects.mail-server.settings = let

      image = { pkgs, ... }: {
        project.name = "mail-server";
        networks = {
          external_network.internal = false;
          internal_network.internal = true;
          redis_network.internal = true;
          ldap_network.internal = true;
        };
        services = let
          antivirusPort = 15407;
          antispamPort = 11335;
          antispamControllerPort = 11336;
          lmtpPort = 24;
          authPort = 5447;
          userdbPort = 5448;
          dkimPort = 5734;
          redisPort = 6379;

        in {
          smtp = {
            service = {
              networks = [
                # Needs access to internet to forward emails & lookup hosts
                "external_network"
                # For auth lookups
                "ldap_network"
                "internal_network"
              ];
              capabilities.SYS_ADMIN = true;
              volumes = [
                "${dovecotLdapConfigPath}:/run/dovecot2/conf.d/ldap.conf:ro"
                "${postfixLdapRecipientsPath}:/run/mail-server/ldap-recipients.cf:ro"
                "${cfg.smtp.ssl-directory}:/run/certs/smtp"
                # The mail queue. Without this it lives in the container's
                # writable layer, and postfix-setup recreates
                # queue/{pid,public,maildrop} from scratch on every start --
                # so deferred and in-flight mail was silently discarded
                # whenever the container was recreated, which is most
                # rebuilds. No bounce, no log line naming what was lost.
                "${cfg.state-directory}/postfix:/var/lib/postfix"
              ];
              ports = [ "25:25" "587:587" "465:465" ];
              depends_on = [ "imap" "ldap-proxy" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                imports = [ ./dovecot.nix ./postfix.nix ];

                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];

                networking = {
                  useDHCP = false;
                  firewall.enable = false;
                };

                fudo.mail.postfix = {
                  enable = true;
                  policy-spf.enable = cfg.smtp.spf.enable;
                  debug = cfg.debug;
                  domain = cfg.primary-domain;
                  local-domains = cfg.extra-domains;
                  hostname = cfg.smtp.hostname;
                  trusted-networks = let
                    isIpv6 = net: !isNull (builtins.match ".+:.+" net);
                    addIpv6Escape = net:
                      let components = builtins.split "/" net;
                      in "[${elemAt components 0}]/${elemAt components 2}";
                    escapeIpv6 = net:
                      if isIpv6 net then addIpv6Escape net else net;
                  in map escapeIpv6 cfg.trusted-networks;
                  blacklist = {
                    senders = cfg.blacklist.senders;
                    recipients = cfg.blacklist.recipients;
                    dns = cfg.blacklist.dns;
                  };
                  aliases = {
                    user-aliases = cfg.aliases.user-aliases;
                    alias-users = cfg.aliases.alias-users;
                  };
                  ssl = {
                    certificate =
                      "/run/certs/smtp/fullchain.pem"; # FIXME: or just cert?
                    private-key = "/run/certs/smtp/key.pem";
                  };
                  sasl-domain = cfg.sasl-domain;
                  message-size-limit = cfg.message-size-limit;
                  ports.metrics = 5035;
                  rspamd-server = {
                    host = "antispam";
                    port = antispamPort;
                  };
                  lmtp-server = {
                    host = "imap";
                    port = lmtpPort;
                  };
                  dkim-server = {
                    host = "dkim";
                    port = dkimPort;
                  };
                  ldap-conf = "/run/dovecot2/conf.d/ldap.conf";
                  ldap-recipient-maps = "/run/mail-server/ldap-recipients.cf";
                };
              };
            };
          };
          imap = {
            service = {
              networks = [
                "internal_network"
                "external_network"
                # For authentication
                "ldap_network"
              ];
              capabilities.SYS_ADMIN = true;
              ports = [ "143:143" "993:993" ];
              volumes = [
                "${cfg.state-directory}/dovecot:/state"
                "${dovecotLdapConfigPath}:/run/dovecot2/conf.d/ldap.conf:ro"
                "${dovecotAdminConfigPath}:/run/dovecot2/conf.d/admin.conf:ro"
                "${cfg.imap.ssl-directory}:/run/certs/imap:ro"
                "${cfg.state-directory}/dovecot-dhparams:/var/lib/dhparams"
                "${cfg.state-directory}/mail:/mail"
              ];
              depends_on = [ "antispam" "ldap-proxy" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                imports = [ ./dovecot.nix ];
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                networking.firewall.enable = false;
                fudo.mail.dovecot = {
                  enable = true;
                  debug = cfg.debug;
                  state-directory = "/state";
                  mail-directory = "/mail";
                  ports = {
                    lmtp = lmtpPort;
                    auth = authPort;
                    userdb = userdbPort;
                    metrics = 5036;
                  };
                  mail-user = cfg.mail-user;
                  mail-group = cfg.mail-group;
                  ssl = {
                    certificate = "/run/certs/imap/fullchain.pem";
                    private-key = "/run/certs/imap/key.pem";
                  };
                  rspamd = {
                    host = "antispam";
                    port = antispamPort;
                  };
                  ldap-conf = "/run/dovecot2/conf.d/ldap.conf";
                  admin-conf = "/run/dovecot2/conf.d/admin.conf";
                  quota = {
                    enable = cfg.quota.enable;
                    limit = cfg.quota.limit;
                    exemptions = cfg.quota.exemptions;
                    admin-email = cfg.admin-email;
                  };
                };
              };
            };
          };
          ldap-proxy.service = {
            image = cfg.images.ldap-proxy;
            restart = "always";
            networks = [
              # Needs access to external network to talk to Authentik
              "external_network"
              "ldap_network"
            ];
            env_file = [ ldapProxyEnvPath ];
          };
          antispam = {
            service = {
              networks = [
                "internal_network"
                # Needs external access for blacklist checks
                "external_network"
                "redis_network"
              ];
              capabilities.SYS_ADMIN = true;
              depends_on = [ "antivirus" "redis" ];
              # Gives rspamd.nix's own boot-time assembly (redis.password-file,
              # read inside the container) something to read -- the container
              # sees it at this path regardless of whether redisPasswdPath is
              # a build-seed store path or an Aegis runtime one on the host.
              volumes = [ "${redisPasswdPath}:/run/redis-client/passwd:ro" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                imports = [ ./rspamd.nix ];
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                networking.firewall.enable = false;
                fudo.mail.rspamd = {
                  enable = true;
                  inherit (cfg.antispam) hyperscan;
                  ports = {
                    milter = antispamPort;
                    controller = antispamControllerPort;
                  };
                  antivirus = {
                    host = "antivirus";
                    port = antivirusPort;
                  };
                  redis = {
                    host = "redis";
                    port = redisPort;
                    password-file = "/run/redis-client/passwd";
                  };
                };
              };
            };
          };
          antivirus = {
            service = {
              networks = [
                "internal_network"
                # Needs external access for database updates
                "external_network"
              ];
              capabilities.SYS_ADMIN = true;
              volumes = [ "${cfg.state-directory}/antivirus:/state" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                imports = [ ./clamav.nix ];
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                networking.firewall.enable = false;
                fudo.mail.clamav = {
                  enable = true;
                  state-directory = "/state";
                  port = antivirusPort;
                };
              };
            };
          };
          dkim = {
            service = {
              networks = [ "internal_network" ];
              capabilities.SYS_ADMIN = true;
              volumes = [ "${cfg.state-directory}/dkim:/var/lib/opendkim" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                imports = [ ./dkim.nix ];
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                networking.firewall.enable = false;
                fudo.mail.dkim = {
                  enable = true;
                  debug = cfg.debug;
                  port = dkimPort;
                  state-directory = "/state";
                  domains = [ cfg.primary-domain ] ++ cfg.extra-domains;
                };
              };
            };
          };
          redis = {
            service = {
              volumes = [
                # /var/lib/redis-rspamd, not /var/lib/redis: the NixOS redis
                # module derives its data directory from the server NAME --
                # `services.redis.servers."rspamd"` gets StateDirectory=
                # redis-rspamd. Mounting /var/lib/redis meant nothing was
                # ever written to the mount, and every Bayes corpus, neural
                # model, reputation score and fuzzy hash lived in the
                # container's ephemeral layer until the next rebuild threw
                # it away. Keep the two in sync if the server is renamed.
                "${cfg.state-directory}/redis:/var/lib/redis-rspamd"
                "${redisPasswdPath}:/run/redis/passwd:ro"
              ];
              networks = [ "redis_network" ];
              capabilities.SYS_ADMIN = true;
            };
            nixos = {
              useSystemd = true;
              configuration = {
                networking.firewall.enable = false;
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                services.redis.servers."rspamd" = {
                  enable = true;
                  bind = null; # null -> all
                  port = redisPort;
                  requirePassFile = "/run/redis/passwd";
                };
              };
            };
          };
          metrics-proxy = {
            service = {
              networks = [ "internal_network" "external_network" ];
              ports = [ "${toString cfg.metrics-port}:80" ];
              depends_on = [ "smtp" "imap" "antispam" ];
              capabilities.SYS_ADMIN = true;
            };
            nixos = {
              useSystemd = true;
              configuration = {
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                networking.firewall.enable = false;
                services.nginx = {
                  enable = true;
                  recommendedProxySettings = true;
                  recommendedGzipSettings = true;
                  recommendedOptimisation = true;

                  commonHttpConfig = ''
                    log_format with_response_time '$remote_addr - $remote_user [$time_local] '
                                 '"$request" $status $body_bytes_sent '
                                 '"$http_referer" "$http_user_agent" '
                                 '"$request_time" "$upstream_response_time"';
                    access_log /var/log/nginx/access.log with_response_time;
                  '';

                  virtualHosts."_" = {
                    default = true;
                    locations = {
                      "/metrics/postfix".proxyPass = "http://smtp:5035/metrics";
                      "/metrics/dovecot".proxyPass = "http://imap:5036/metrics";
                      # Rspamd serves Prometheus metrics natively from the
                      # controller worker's /metrics endpoint.
                      "/metrics/rspamd".proxyPass =
                        "http://antispam:${toString antispamControllerPort}/metrics";
                    };
                  };
                };
              };
            };
          };
        };
      };
    in { imports = [ image ]; };
  };
}
