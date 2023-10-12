{ config, lib, pkgs, ... }:

with lib;
let
  cfg = config.fudo.mail.dovecot;

  sieveDirectory = "${cfg.state-directory}/sieves";

in {
  options.fudo.mail.dovecot = with types; {
    enable = mkEnableOption "Enable Dovecot2 IMAP server.";

    debug = mkEnableOption "Enable debug logs.";

    state-directory = mkOption {
      type = str;
      description = "Directory at which to store server state.";
    };

    mail-directory = mkOption {
      type = str;
      description = "Directory at which to store user email.";
    };

    ports = {
      lmtp = mkOption {
        type = port;
        description = "Port on which to listen for LMTP connections.";
        default = 24;
      };
      auth = mkOption {
        type = port;
        description = "Port on which to listen for auth requests.";
        default = 5447;
      };
      userdb = mkOption {
        type = port;
        description = "Port on which to listen for userdb requests.";
        default = 5448;
      };
      metrics = mkOption {
        type = port;
        description = "Port on which to serve metrics data.";
        default = 5034;
      };
    };

    mail-user = mkOption {
      type = str;
      description = "User as which to run store & access mail.";
      default = "fudo-mail";
    };

    mail-group = mkOption {
      type = str;
      description = "Group as which to store & access mail.";
      default = "fudo-mail";
    };

    ssl = {
      certificate = mkOption {
        type = str;
        description = "Location of the Dovecot SSL certificate.";
      };

      private-key = mkOption {
        type = str;
        description = "Location of the Dovecot SSL private key.";
      };
    };

    metrics = {
      user = mkOption {
        type = str;
        description = "User as which to fetch metrics.";
        default = "dovecot-metrics";
      };

      group = mkOption {
        type = str;
        description = "Group as which to fetch metrics.";
        default = "dovecot-metrics";
      };
    };

    mailboxes = let
      mailboxOpts = { name, ... }: {
        options = {
          auto = mkOption {
            type = enum [ "no" "create" "subscribe" ];
            description = "Whether to auto-create/subscribe.";
            default = "no";
          };
          specialUse = mkOption {
            type = nullOr (enum [
              "All"
              "Archive"
              "Drafts"
              "Flagged"
              "Junk"
              "Sent"
              "Trash"
            ]);
            description = "Mailbox special use.";
            default = null;
          };
          autoexpunge = mkOption {
            type = nullOr str;
            description =
              "How long to wait before clearing mail from this mailbox. Null is never.";
            default = null;
          };
        };
      };
    in mkOption {
      type = attrsOf (submodule mailboxOpts);
      description = "Mailboxes to be created for dovecot.";
      default = {
        Trash = {
          auto = "create";
          specialUse = "Trash";
          autoexpunge = "30d";
        };
        Junk = {
          auto = "create";
          specialUse = "Junk";
          autoexpunge = "60d";
        };
        Drafts = {
          auto = "create";
          specialUse = "Drafts";
          autoexpunge = "60d";
        };
        Sent = {
          auto = "create";
          specialUse = "Sent";
        };
        Archive = {
          auto = "no";
          specialUse = "Archive";
        };
        Flagged = {
          auto = "subscribe";
          specialUse = "Flagged";
        };
      };
    };

    rspamd = {
      host = mkOption {
        type = str;
        description = "Host to which spam/ham will be forwarded.";
      };
      port = mkOption {
        type = port;
        description = "Port to which spam/ham will be forwarded.";
      };
    };

    solr = {
      host = mkOption {
        type = str;
        description = "Host providing full-text search with Solr.";
      };
      port = mkOption {
        type = port;
        description = "Port on which Solr is listening.";
      };
    };

    max-user-connections = mkOption {
      type = int;
      description = "Maximum allowed simultaneous connections by one user.";
      default = 5;
    };

    ldap-conf = mkOption {
      type = str;
      description = "Path to LDAP dovecot2 configuration.";
    };
  };

  config = mkIf cfg.enable {
    users = {
      users = {
        "${cfg.mail-user}" = {
          isSystemUser = true;
          group = cfg.mail-group;
          uid = 5025;
        };
        "${cfg.metrics.user}" = {
          isSystemUser = true;
          group = cfg.metrics.group;
        };
      };
      groups = {
        "${cfg.mail-group}" = {
          members = [ cfg.mail-user ];
          gid = 5025;
        };
        "${cfg.metrics.group}".members = [ cfg.metrics.user ];
      };
    };

    # FIXME: TEMPORARY FOR TESTING
    environment.systemPackages = with pkgs; [ openldap ];

    systemd = {
      tmpfiles.rules = [
        "d ${cfg.state-directory}        0711 root root - -"
        "d ${cfg.mail-directory}         0750 ${cfg.mail-user} ${cfg.mail-group} - -"
        "d ${cfg.state-directory}/sieves 0750 ${config.services.dovecot2.user} ${config.services.dovecot2.group} - -"
      ];

      timers = {
        solr-commit = {
          wantedBy = [ "timers.target" "dovecot2.service" ];
          timerConfig = {
            OnBootSec = "5m";
            OnUnitActiveSec = "5m";
            Unit = "solr-commit.service";
          };
        };
        solr-optimize = {
          wantedBy = [ "timers.target" "dovecot2.service" ];
          timerConfig = {
            OnBootSec = "12h";
            OnUnitActiveSec = "12h";
            Unit = "solr-optimize.service";
          };
        };
      };

      services = let
        solrJob = params: {
          requires = [ "dovecot2.service" ];
          serviceConfig = {
            ExecStart = "${pkgs.curl}/bin/curl http://${cfg.solr.host}:${
                toString cfg.solr.port
              }/?${params}";
            PrivateDevices = true;
            PrivateTmp = true;
            PrivateMounts = true;
            ProtectControlGroups = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectSystem = true;
            ProtectHome = true;
            ProtectClock = true;
            ProtectKernelLogs = true;
            Type = "oneshot";
          };
        };
      in {
        solr-commit = solrJob "commit=true";

        solr-optimize = solrJob "optimize=true";

        prometheus-dovecot-exporter = {
          requires = [ "dovecot2.service" ];
          after = [ "dovecot2.service" ];
        };

        dovecot-sieve-generator = let
          isRegularFile = _: type: type == "regular";
          sieves = filterAttrs isRegularFile (builtins.readDir ./sieves);
          headOrNull = lst: if lst == [ ] then null else head lst;
          stripExt = ext: filename:
            headOrNull (builtins.match "(.+)[.]${ext}$" filename);
          compileFile = filename: _:
            let
              filePath = ./sieves + "/${filename}";
              fileBaseName = stripExt "sieve" filename;
            in ''
              if [ -f "${sieveDirectory}/${fileBaseName}.sieve" ]; then
                rm "${sieveDirectory}/${fileBaseName}.sieve" "${sieveDirectory}/${fileBaseName}.svbin"
              fi
              cp ${filePath} "${sieveDirectory}/${fileBaseName}.sieve"
              sievec "${sieveDirectory}/${fileBaseName}.sieve" "${sieveDirectory}/${fileBaseName}.svbin"
              chmod u+w "${sieveDirectory}/${fileBaseName}.sieve"
            '';
        in {
          wantedBy = [ "dovecot2.service" ];
          after = [ "dovecot2.service" ];
          path = with pkgs; [ dovecot_pigeonhole ];
          serviceConfig = {
            User = config.services.dovecot2.user;
            ReadWritePaths = [ sieveDirectory "/run/dovecot2" ];
            ExecStart = pkgs.writeShellScript "generate-sieves.sh"
              (concatStringsSep "\n" (mapAttrsToList compileFile sieves));
            PrivateDevices = true;
            PrivateTmp = true;
            PrivateMounts = true;
            ProtectControlGroups = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectSystem = true;
            ProtectHome = true;
            ProtectClock = true;
            ProtectKernelLogs = true;
            Type = "oneshot";
          };
        };
      };
    };

    services = {
      prometheus.exporters.dovecot = {
        enable = true;
        scopes = [ "user" "global" ];
        user = cfg.metrics.user;
        listenAddress = "127.0.0.1";
        port = cfg.ports.metrics;
        socketPath = "/var/run/dovecot2/old-stats";
      };

      dovecot2 = {
        enable = true;
        enableImap = true;
        enableLmtp = true;
        enablePAM = false;

        mailUser = cfg.mail-user;
        mailGroup = cfg.mail-group;
        mailLocation = "maildir:${cfg.mail-directory}/%u/";
        createMailUser = false;

        sslServerCert = cfg.ssl.certificate;
        sslServerKey = cfg.ssl.private-key;

        mailboxes = cfg.mailboxes;

        modules = with pkgs; [ dovecot_pigeonhole ];
        protocols = [ "sieve" ];

        mailPlugins.globally.enable = [ "old_stats" ];

        sieveScripts = {
          after = builtins.toFile "spam.sieve" ''
            require "fileinto";

            if header :is "X-Spam" "Yes" {
              fileinto "Junk";
              stop;
            }
          '';
        };

        extraConfig = let
          # Add learn_ham & learn_spam to dovecot2 path for use by sieves
          pipeBin = let
            teachRspamd = msg:
              pkgs.writeShellApplication {
                name = "rspamd_${msg}";
                runtimeInputs = with pkgs; [ rspamd ];
                text = "exec rspamc -h ${cfg.rspamd.host}:${
                    toString cfg.rspamd.port
                  } ${msg}";
              };
            learnHam = teachRspamd "learn_ham";
            learnSpam = teachRspamd "learn_spam";
          in pkgs.buildEnv {
            name = "rspam_pipe_bin";
            paths = [ learnHam learnSpam ];
          };

          mailUserUid = config.users.users."${cfg.mail-user}".uid;
          mailUserGid = config.users.group."${cfg.mail-group}".gid;
        in ''
          ## Extra Config

          mail_plugins = $mail_plugins fts fts_solr

          ${lib.optionalString cfg.debug ''
            mail_debug = yes
            auth_debug = yes
            verbose_ssl = yes
          ''}

          protocol imap {
            mail_max_userip_connections = ${toString cfg.max-user-connections}
            mail_plugins = $mail_plugins imap_sieve
          }

          protocol lmtp {
            mail_plugins = $mail_plugins sieve
          }

          plugin {
            fts = solr
            fts_solr = url=http://${cfg.solr.host}:${
              toString cfg.solr.port
            }/solr/dovecot
          }

          mail_access_groups = ${cfg.mail-group}

          # When looking up usernames, just use the name, not the full address
          auth_username_format = %n

          auth_mechanisms = login plain

          service lmtp {
            # Enable logging in debug mode
            ${optionalString cfg.debug "executable = lmtp -L"}

            inet_listener dovecot-lmtp {
              address = 0.0.0.0
              port = ${toString cfg.ports.lmtp}
            }

            ## Drop privs, since all mail is owned by one user
            # user = ${cfg.mail-user}
            # group = ${cfg.mail-group}
            ### Necessary bceause:
            ## - for security reasons lmtp service must be started as root since
            ##   version 2.2.36. lmtp will drop root privileges after initialisation but it needs
            ##   to open /self/proc/io as root before that."
            ## See: https://dovecot.org/list/dovecot/2019-July/116674.html
            user = root
          }

          passdb {
            driver = ldap
            args = ${cfg.ldap-conf}
          }

          # All users map to one actual system user
          userdb {
            driver = static
            args = uid=${toString mailUserUid} home=${cfg.mail-directory}/%u
          }

          service imap {
            vsz_limit = 1024M
          }

          namespace inbox {
            separator = "/"
            inbox = yes
          }

          plugin {
            sieve_plugins = sieve_imapsieve sieve_extprograms
            sieve = file:${cfg.state-directory}/sieves/%u/scripts;active=${cfg.state-directory}/sieves/%u/active.sieve
            sieve_default = file:${sieveDirectory}/%u/default.sieve
            sieve_default_name = default
            # From elsewhere to Spam folder
            imapsieve_mailbox1_name = Junk
            imapsieve_mailbox1_causes = COPY
            imapsieve_mailbox1_before = file:${sieveDirectory}/spam.svbin
            # From Spam folder to elsewhere
            imapsieve_mailbox2_name = *
            imapsieve_mailbox2_from = Junk
            imapsieve_mailbox2_causes = COPY
            imapsieve_mailbox2_before = file:${sieveDirectory}/ham.svbin

            sieve_pipe_bin_dir = ${pipeBin}/bin
            sieve_global_extensions = +vnd.dovecot.pipe +vnd.dovecot.environment
          }

          recipient_delimiter = +

          lmtp_save_to_detail_mailbox = yes

          lda_mailbox_autosubscribe = yes
          lda_mailbox_autocreate = yes

          service old-stats {
            unix_listener old-stats {
              user = ${cfg.metrics.user}
              group = ${cfg.metrics.group}
            }
            fifo_listener old-stats-mail {
              mode = 0660
              user = ${config.services.dovecot2.user}
              group = ${config.services.dovecot2.group}
            }
            fifo_listener old-stats-user {
              mode = 0660
              user = ${config.services.dovecot2.user}
              group = ${config.services.dovecot2.group}
            }
          }

          plugin {
            old_stats_refresh = 30 secs
            old_stats_track_cmds = yes
          }
        '';
      };
    };
  };
}
