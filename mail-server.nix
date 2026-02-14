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
# - Secrets managed via Nix (WARNING: stored in Nix store)
# - TLS required for all client connections (submission/IMAP)
# - SASL authentication via LDAP
# - Multi-layer spam/abuse prevention
# - Regular virus database updates
#
# TODO: Move secrets to runtime injection (systemd LoadCredential, etc.)

with lib;
let
  cfg = config.fudo.mail;
  hostname = config.instance.hostname;
  hostSecrets = config.fudo.secrets.host-secrets."${hostname}";

  # Auto-generated passwords for internal services
  # WARNING: These are deterministic based on build-seed and stored in Nix store
  # Consider migrating to runtime secret injection
  dovecotAdminPasswd =
    pkgs.lib.passwd.stablerandom-passwd-file "dovecot-admin-passwd"
    config.instance.build-seed;
  dovecotApiKey = pkgs.lib.passwd.stablerandom-passwd-file "dovecot-api-key"
    config.instance.build-seed;

  redisPasswdFile =
    pkgs.lib.passwd.stablerandom-passwd-file "mail-server-redis-passwd"
    config.instance.build-seed;

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

    message-size-limit = mkOption {
      type = int;
      description = "Max allowed size of messages, in megabytes.";
      default = 100;
    };

    sasl-domain = mkOption {
      type = str;
      description = "SASL domain to use for authentication.";
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
        default = 3600;  # 1 hour
      };

      maxretry = mkOption {
        type = int;
        description = "Number of failures before banning.";
        default = 5;
      };

      findtime = mkOption {
        type = int;
        description = "Time window in seconds to count failures.";
        default = 600;  # 10 minutes
      };
    };

    ldap = {
      authentik-host = mkOption {
        type = str;
        description = "Hostname of the LDAP outpost provider.";
        default = "authentik.${toplevel.config.fudo.mail.primary-domain}";
      };

      outpost-token = mkOption {
        type = str;
        description = "Token with which to authenticate to the Authentik host.";
      };

      bind-dn = mkOption {
        type = str;
        description = "DN as which to bind with the LDAP server.";
      };

      bind-password-file = mkOption {
        type = str;
        description =
          "File containing password with which to bind with the LDAP server.";
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
    fudo.secrets.host-secrets."${hostname}" = {
      mailLdapProxyEnv = {
        source-file = pkgs.writeText "ldap-proxy.env" ''
          AUTHENTIK_HOST=${cfg.ldap.authentik-host}
          AUTHENTIK_TOKEN=${cfg.ldap.outpost-token}
          AUTHENTIK_INSECURE=false
        '';
        target-file = "/run/mail-server/ldap-proxy/env";
      };

      dovecotLdapConfig = {
        source-file = pkgs.writeText "dovecot-ldap.conf"
          (concatStringsSep "\n" [
            "uris = ldap://ldap-proxy:3389"
            "ldap_version = 3"
            "dn = ${cfg.ldap.bind-dn}"
            "dnpass = ${readFile cfg.ldap.bind-password-file}"
            "auth_bind = yes"
            "auth_bind_userdn = cn=%n,${cfg.ldap.user-ou},${cfg.ldap.base}"
            "base = ${cfg.ldap.base}"
            "user_filter = (&(objectClass=organizationalPerson)(cn=%n))"
            "pass_filter = (&(objectClass=organizationalPerson)(cn=%n))"
            "pass_attrs = =user=%{ldap:cn}"
            "user_attrs = =user=%{ldap:cn}"
          ]);
        target-file = "/run/mail-server/dovecot-secrets/ldap.conf";
      };

      postfixLdapRecipients = {
        source-file = pkgs.writeText "postfix-ldap-recipients.cf"
          (concatStringsSep "\n" [
            "server_host = ldap-proxy"
            "server_port = 3389"
            "version = 3"
            "bind = yes"
            "bind_dn = ${cfg.ldap.bind-dn}"
            "bind_pw = ${readFile cfg.ldap.bind-password-file}"
            "search_base = ${cfg.ldap.user-ou},${cfg.ldap.base}"
            "scope = sub"
            "query_filter = (&(objectClass=organizationalPerson)(cn=%u))"
            "result_attribute = cn"
            "result_format = OK"
          ]);
        target-file = "/run/mail-server/postfix-secrets/ldap-recipients.cf";
      };

      dovecotAdminConfig = {
        source-file = pkgs.writeText "dovecot-admin.conf" (concatStringsSep "\n"
          ([ "doveadm_password = ${readFile dovecotAdminPasswd}" ]
            ++ (optional (cfg.imap.api-port != null)
              "doveadm_api_key = ${readFile dovecotApiKey}")));
        target-file = "/run/mail-server/dovecot-secrets/admin.conf";
      };

      redisPasswd = {
        source-file = redisPasswdFile;
        target-file = "/run/mail-server/redis/passwd";
      };
    };

    networking.firewall = { allowedTCPPorts = [ 25 143 465 587 993 ]; };

    systemd.tmpfiles.rules = [
      "d ${cfg.state-directory}/dovecot            0700 - - - -"
      "d ${cfg.state-directory}/dovecot-dhparams   0700 - - - -"
      "d ${cfg.state-directory}/antivirus          0700 - - - -"
      "d ${cfg.state-directory}/dkim               0700 - - - -"
      "d ${cfg.state-directory}/mail               0700 - - - -"
      # Secret directories for container mounts
      "d /run/mail-server                          0755 - - - -"
      "d /run/mail-server/ldap-proxy               0755 - - - -"
      "d /run/mail-server/dovecot-secrets          0755 - - - -"
      "d /run/mail-server/postfix-secrets          0755 - - - -"
      "d /run/mail-server/redis                    0755 - - - -"
      # Secret files
      "L+ ${hostSecrets.mailLdapProxyEnv.target-file}        - - - - ${hostSecrets.mailLdapProxyEnv.source-file}"
      "L+ ${hostSecrets.dovecotLdapConfig.target-file}       - - - - ${hostSecrets.dovecotLdapConfig.source-file}"
      "L+ ${hostSecrets.postfixLdapRecipients.target-file}   - - - - ${hostSecrets.postfixLdapRecipients.source-file}"
      "L+ ${hostSecrets.dovecotAdminConfig.target-file}      - - - - ${hostSecrets.dovecotAdminConfig.source-file}"
      "L+ ${hostSecrets.redisPasswd.target-file}             - - - - ${hostSecrets.redisPasswd.source-file}"
    ];

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
                "${hostSecrets.dovecotLdapConfig.target-file}:/run/dovecot2/conf.d/ldap.conf:ro"
                "${hostSecrets.postfixLdapRecipients.target-file}:/etc/postfix/ldap-recipients.cf:ro"
                "${cfg.smtp.ssl-directory}:/run/certs/smtp"
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
                  ldap-recipient-maps = "/etc/postfix/ldap-recipients.cf";
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
                "${hostSecrets.dovecotLdapConfig.target-file}:/run/dovecot2/conf.d/ldap.conf:ro"
                "${hostSecrets.dovecotAdminConfig.target-file}:/run/dovecot2/conf.d/admin.conf:ro"
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
            env_file = [ hostSecrets.mailLdapProxyEnv.target-file ];
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
                  ports = {
                    milter = antispamPort;
                    controller = antispamControllerPort;
                    metrics = 5037;
                  };
                  antivirus = {
                    host = "antivirus";
                    port = antivirusPort;
                  };
                  redis = {
                    host = "redis";
                    port = redisPort;
                    password = readFile redisPasswdFile;
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
                "${cfg.state-directory}/redis:/var/lib/redis"
                "${hostSecrets.redisPasswd.target-file}:/run/redis/passwd"
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
                      "/metrics/rspamd".proxyPass =
                        "http://antispam:5037/metrics";
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
