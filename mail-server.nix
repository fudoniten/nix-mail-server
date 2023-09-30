{ config, lib, pkgs, ... }@toplevel:

with lib;
let
  cfg = config.fudo.mail;
  hostname = config.instance.hostname;
  hostSecrets = config.fudo.secrets.host-secrets."${hostname}";
  metricsPort = 5034;

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
          "Map of alias user to list of users who should receive email..";
        default = { };
      };
    };

    metrics-port = mkOption {
      type = port;
      description = "Port on which to serve metrics.";
      default = metricsPort;
    };

    trusted-networks = mkOption {
      type = listOf str;
      description = "List of networks to be considered trusted.";
      default = [ ];
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

      member-ou = mkOption {
        type = str;
        description = "Organizational unit containing users.";
        default = "ou=members";
      };
    };

    images.ldap-proxy = mkOption {
      type = str;
      description = "Docker image to use for LDAP proxy.";
      default = "ghcr.io/goauthentik/ldap";
    };

    smtp = {
      hostname = mkOption {
        type = str;
        description =
          "Hostname too use for the SMTP server. Must resolve to this host.";
        default = "smtp.${config.fudo.mail.primary-domain}";
      };

      ssl-directory = mkOption {
        type = str;
        description =
          "Directory containing SSL certificates for SMTP hostname.";
      };
    };

    imap = {
      hostname = mkOption {
        type = str;
        description =
          "Hostname too use for the IMAP server. Must resolve to this host.";
        default = "imap.${config.fudo.mail.primary-domain}";
      };

      ssl-directory = mkOption {
        type = str;
        description =
          "Directory containing SSL certificates for IMAP hostname.";
      };
    };
  };

  config = mkIf cfg.enable {
    services = {
      nginx = {
        virtualHosts = {
          "${cfg.smtp.hostname}".locations."/metrics" = {
            proxyPass = "http://localhost:${toString metricsPort}/metrics";
          };
          "${cfg.imap.hostname}".locations."/metrics" = {
            proxyPass = "http://localhost:${toString metricsPort}/metrics";
          };
        };
      };
    };

    fudo.secrets.host-secrets."${hostname}" = {
      mailLdapProxyEnv = {
        source-file = pkgs.writeText "ldap-proxy.env" ''
          AUTHENTIK_HOST=${cfg.ldap.authentik-host}
          AUTHENTIK_TOKEN=${cfg.ldap.outpost-token}
          AUTHENTIK_INSECURE=false
        '';
        target-file = "/run/ldap-proxy/env";
      };

      dovecotLdapConfig = {
        source-file = pkgs.writeText "dovecot-ldap.conf"
          (concatStringsSep "\n" [
            "uris = ldap://ldap-proxy:3389"
            "ldap_version = 3"
            "dn = ${cfg.ldap.bind-dn}"
            "dnpass = ${readFile cfg.ldap.bind-password-file}"
            "auth_bind = yes"
            "auth_bind_userdn = cn=%u,${cfg.ldap.member-ou},${cfg.ldap.base}"
            "base = ${cfg.ldap.base}"
            # "user_filter = (&(objectClass=organizationalPerson)(cn=%n))"
          ]);
        target-file = "/run/dovecot-secret/ldap.conf";
      };
    };

    systemd.tmpfiles.rules = [
      "d ${cfg.state-directory}/dovecot            0700 - - - -"
      "d ${cfg.state-directory}/dovecot-dhparams   0700 - - - -"
      "d ${cfg.state-directory}/antivirus          0700 - - - -"
      "d ${cfg.state-directory}/dkim               0700 - - - -"
    ];

    virtualisation.arion.projects.mail-server.settings = let
      redisPasswdFile =
        pkgs.lib.passwd.stablerandom-passwd-file "mail-server-redis-passwd"
        config.instance.build-seed;

      image = { pkgs, ... }: {
        project.name = "mail-server";
        networks = {
          external_network.internal = false;
          internal_network.internal = true;
          redis_network.internal = true;
        };
        services = let
          antivirusPort = 15407;
          antispamPort = 11335;
          antispamControllerPort = 11336;
          lmtpPort = 24;
          authPort = 5447;
          userdbPort = 5448;
          dkimPort = 5734;

        in {
          smtp = {
            service = {
              networks = [
                "internal_network"
                # Needs access to internet to forward emails
                "external_network"
              ];
              volumes = [
                "${hostSecrets.dovecotLdapConfig.target-file}:/run/dovecot2/conf.d/ldap.conf:ro"
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

                fudo.mail.postfix = {
                  enable = true;
                  debug = cfg.debug;
                  domain = cfg.primary-domain;
                  local-domains = cfg.extra-domains;
                  hostname = cfg.smtp.hostname;
                  trusted-networks = cfg.trusted-networks;
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
                  ports = { metrics = metricsPort; };
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
                };
              };
            };
          };
          imap = {
            service = {
              networks = [ "internal_network" "external_network" ];
              ports = [ "143:143" "993:993" ];
              volumes = [
                "${cfg.state-directory}/dovecot:/state"
                "${hostSecrets.dovecotLdapConfig.target-file}:/run/dovecot2/conf.d/ldap.conf:ro"
                "${cfg.imap.ssl-directory}:/run/certs/imap"
                "${cfg.state-directory}/dovecot-dhparams:/var/lib/dhparams"
              ];
              depends_on = [ "antispam" "ldap-proxy" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                imports = [ ./dovecot.nix ];
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                fudo.mail.dovecot = {
                  enable = true;
                  debug = cfg.debug;
                  state-directory = "/state";
                  ports = {
                    lmtp = lmtpPort;
                    auth = authPort;
                    userdb = userdbPort;
                    metrics = metricsPort;
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
                };
              };
            };
          };
          ldap-proxy.service = {
            image = cfg.images.ldap-proxy;
            restart = "always";
            networks = [
              "internal_network"
              # Needs access to external network for user lookups
              "external_network"
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
                fudo.mail.rspamd = {
                  enable = true;
                  ports = {
                    milter = antispamPort;
                    controller = antispamControllerPort;
                    metrics = metricsPort;
                  };
                  antivirus = {
                    host = "antivirus";
                    port = antivirusPort;
                  };
                  redis.password = readFile redisPasswdFile;
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
              volumes = [ "${cfg.state-directory}/antivirus:/state" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                imports = [ ./clamav.nix ];
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                networking.firewall = {
                  enable = true;
                  allowedTCPPorts = [ antivirusPort ];
                  allowedUDPPorts = [ antivirusPort ];
                };
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
              volumes = [ "${cfg.state-directory}/dkim:/var/lib/opendkim" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                imports = [ ./dkim.nix ];
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
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
                "${redisPasswdFile}:/run/redis/passwd"
              ];
              networks = [ "redis_network" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                services.redis.servers."rspamd" = {
                  enable = true;
                  # null -> all
                  bind = null;
                  port = 6379;
                  requirePassFile = "/run/redis/passwd";
                };
              };
            };
          };
          metrics-proxy = {
            service = {
              networks = [ "internal_network" ];
              ports = [ "${toString cfg.metrics-port}:80" ];
              depends_on = [ "smtp" "imap" "antispam" ];
            };
            nixos = {
              useSystemd = true;
              configuration = {
                boot.tmp.useTmpfs = true;
                system.nssModules = lib.mkForce [ ];
                services.nginx = {
                  enable = true;
                  recommendedProxySettings = true;
                  recommendedGzipSettings = true;
                  recommendedOptimisation = true;
                  virtualHosts.localhost = {
                    default = true;
                    locations = {
                      "/postfix" = {
                        proxyPass = "http://smtp:${toString metricsPort}/";
                      };
                      "/dovecot" = {
                        proxyPass = "http://imap:${toString metricsPort}/";
                      };
                      "/rspamd" = {
                        proxyPass = "http://antispam:${toString metricsPort}/";
                      };
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
