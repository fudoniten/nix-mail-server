{ config, lib, pkgs, ... }:

with lib; {
  options.fudo.mail = with types; {
    enable = mkEnableOption "Enable mail server.";

    state-directory = mkOption {
      type = str;
      description = "Directory at which to store server state.";
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

    smtp = {
      hostname = mkOption {
        type = str;
        description =
          "Hostname too use for the SMTP server. Must resolve to this host.";
        default = "smtp.${config.fudo.mail.primary-domain}";
      };

      ssl = {
        certificate = mkOption {
          type = str;
          description = "SSL certificate for the SMTP host.";
        };
        private-key = mkOption {
          type = str;
          description = "SSL private key for the SMTP host.";
        };
      };
    };

    imap = {
      hostname = mkOption {
        type = str;
        description =
          "Hostname too use for the IMAP server. Must resolve to this host.";
        default = "imap.${config.fudo.mail.primary-domain}";
      };

      ssl = {
        certificate = mkOption {
          type = str;
          description = "SSL certificate for the IMAP host.";
        };
        private-key = mkOption {
          type = str;
          description = "SSL private key for the IMAP host.";
        };
      };
    };
  };

  config = {
    services.nginx = {
      virtualHosts = {
        "${cfg.smtp.hostname}".locations."/metrics" = {
          proxyPass = "http://localhost:${metricsPort}/metrics";
        };
        "${cfg.imap.hostname}".locations."/metrics" = {
          proxyPass = "http://localhost:${metricsPort}/metrics";
        };
      };
    };

    virtualisation.arion.projects.mail-server.settings = let
      image = { pkgs, ... }: {
        project.name = "fudo-mailserver";
        networks = {
          external_network.internal = false;
          internal_network.internal = true;
        };
        serices = let
          antivirusPort = 15407;
          antispamPort = 11335;
          lmtpPort = 24;
          authPort = 5447;
          userdbPort = 5448;
          metricsPort = 5034;
        in {
          smtp = {
            networks = [
              "internal_network"
              # Needs access to internet to forward emails
              "external_network"
            ];
            ports = [ "25:25" "587:587" "465:465" "2525:2525" ];
            nixos = {
              useSystemd = true;
              configuration = [
                (import ./postfix.nix)
                {
                  boot.tmpOnTmpfs = true;
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
                      user-aliases = cfg.user-aliases;
                      alias-users = cfg.alias-users;
                    };
                    ssl = {
                      certificate = cfg.smtp.ssl.certificate;
                      private-key = cfg.smtp.ssl.private-key;
                    };
                    sasl-domain = cfg.sasl-domain;
                    message-size-limit = cfg.message-size-limit;
                    ports = { metrics = metricsPort; };
                  };
                }
              ];
            };
          };
          imap = {
            networks = [ "internal_network" ];
            ports = [ "143:143" "993:993" ];
            nixos = {
              useSystemd = true;
              configuration = [
                (import ./dovecot.nix)
                {
                  boot.tmpOnTmpfs = true;
                  system.nssModules = lib.mkForce [ ];
                  fudo.mail.dovecot = {
                    enable = true;
                    debug = cfg.debug;
                    state-directory = "${cfg.state-directory}/dovecot";
                    ports = {
                      lmtp = lmtpPort;
                      auth = authPort;
                      userdb = userdbPort;
                      metrics = metricsPort;
                    };
                    mail-user = cfg.mail-user;
                    mail-group = cfg.mail-group;
                    ssl = {
                      certificate = cfg.imap.ssl.certificate;
                      private-key = cfg.imap.ssl.private-key;
                    };
                    rspamd = {
                      host = "antispam";
                      port = antispamPort;
                    };
                    ldap = mkIf cfg.ldap-proxy {
                      host = "ldap-proxy";
                      port = 3389;
                      base = cfg.ldap.base;
                      bind-dn = cfg.ldap.bind-dn;
                      bind-password-file = cfg.ldap.bind-password-file;
                    };
                  };
                }
              ];
            };
          };
          ldap-proxy.service = mkIf (cfg.ldap-proxy != null) {
            image = cfg.images.ldap-proxy;
            restart = "always";
            networks = [
              "internal_network"
              # Needs access to external network for user lookups
              "external_network"
            ];
            envFile = hostSecrets.mailLdapProxyEnv.target-file;
          };
          antispam = {
            networks = [
              "internal_network"
              # Needs external access for blacklist checks
              "external_network"
            ];
            nixos = {
              useSystemd = true;
              configuration = [
                (import ./rspamd.nix)
                {
                  boot.tmpOnTmpfs = true;
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
                  };
                }
              ];
            };
          };
          antivirus = {
            networks = [
              "internal_network"
              # Needs external access for database updates
              "external_network"
            ];
            nixos = {
              useSystemd = true;
              configuration = [
                (import ./clamav.nix)
                {
                  boot.tmpOnTmpfs = true;
                  system.nssModules = lib.mkForce [ ];
                  fudo.mail.clamav = {
                    enable = true;
                    state-directory = "${cfg.state-directory}/rspamd";
                    port = antispamPort;
                  };
                }
              ];
            };
          };
          dkim = {
            networks = [ "internal_network" ];
            nixos = {
              useSystemd = true;
              configuration = [
                (import ./dkim.nix)
                {
                  boot.tmpOnTmpfs = true;
                  system.nssModules = lib.mkForce [ ];
                  fudo.mail.dkim = {
                    enable = true;
                    debug = cfg.debug;
                    domains = [ cfg.primary-domain ] ++ cfg.extra-domains;
                  };
                  port = dkimPort;
                  state-directory = "${cfg.state-directory}/dkim";
                }
              ];
            };
          };
          metrics-proxy = {
            networks = [ "internal_network" ];
            ports = [ "${cfg.metricsPort}:80" ];
            nixos = {
              useSystemd = true;
              configuration = {
                boot.tmpOnTmpfs = true;
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
                        proxyPass = "http://smtp:${metricsPort}/";
                      };
                      "/dovecot" = {
                        proxyPass = "http://imap:${metricsPort}/";
                      };
                      "rspamd" = {
                        proxyPass = "http://antispam:${metricsPort}/";
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
