{ config, lib, pkgs, ... }:

# Dovecot IMAP/LMTP Server Module
#
# Provides email delivery and access via IMAP with advanced features:
# - LMTP for local mail delivery from Postfix
# - IMAP/IMAPS for mail client access
# - Full-text search via Flatcurve (FTS, Xapian-based)
# - Sieve filtering for server-side mail rules
# - LDAP authentication via Authentik
# - Automatic spam learning integration with Rspamd
# - Maildir++ storage format with virtual mailboxes
#
# Architecture choices:
# - Maildir++ format for reliability and compatibility
# - Flatcurve for full-text search (Xapian-based, actively maintained)
# - Sieve for filtering (spam learning, folder sorting, etc.)
# - LDAP auth for centralized user management
# - Virtual plugin for alias handling
# - Quota support disabled (can be enabled per-user if needed)
#
# Mail flow:
# 1. Postfix accepts mail via SMTP
# 2. Mail passes through Rspamd for spam/virus checking
# 3. Postfix delivers to Dovecot via LMTP
# 4. Dovecot applies Sieve filters (spam learning, sorting)
# 5. Mail stored in Maildir format
# 6. Users access via IMAP
#
# Spam learning flow:
# - User moves spam to Junk folder -> ham.sieve -> rspamc learn_spam
# - User moves ham from Junk -> spam.sieve -> rspamc learn_ham

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
      admin = mkOption {
        type = port;
        description = "Port on which to listen for admin requests.";
        default = 5925;
      };
      http-admin = mkOption {
        type = nullOr port;
        description = "Port on which to listen for admin HTTP API requests.";
        default = null;
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

    quota = {
      enable = mkEnableOption "Enable mailbox quotas." // { default = true; };

      limit = mkOption {
        type = str;
        description = "Default quota limit per user (e.g., '10G', '1000M').";
        default = "10G";
      };

      warning-threshold = mkOption {
        type = int;
        description = "Percentage at which to warn users (0-100).";
        default = 90;
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

    max-user-connections = mkOption {
      type = int;
      description = "Maximum allowed simultaneous connections by one user.";
      default = 5;
    };

    ldap-conf = mkOption {
      type = str;
      description = "Path to LDAP dovecot2 configuration.";
    };

    admin-conf = mkOption {
      type = str;
      description = "Path to admin dovecot2 configuration.";
    };
  };

  config = mkIf cfg.enable {
    # User and group for mail storage
    # IMPORTANT: Hardcoded UID/GID 5025 for consistency across systems
    # This ensures mail file ownership remains stable when sharing storage
    # or restoring from backups. Document this requirement for deployments.
    users = {
      users = {
        "${cfg.mail-user}" = {
          isSystemUser = true;
          group = cfg.mail-group;
          uid = 5025; # Hardcoded for cross-system consistency
        };
        "${cfg.metrics.user}" = {
          isSystemUser = true;
          group = cfg.metrics.group;
        };
      };
      groups = {
        "${cfg.mail-group}" = {
          members = [ cfg.mail-user ];
          gid = 5025; # Hardcoded for cross-system consistency
        };
        "${cfg.metrics.group}".members = [ cfg.metrics.user ];
      };
    };

    systemd = {
      # Directory structure:
      # - state-directory: Dovecot runtime state, indexes, Sieve scripts
      # - mail-directory: Actual mail storage (Maildir format)
      # - sieves: Compiled Sieve scripts for filtering
      tmpfiles.rules = [
        "d ${cfg.state-directory}        0711 root root - -"
        "d ${cfg.mail-directory}         0750 ${cfg.mail-user} ${cfg.mail-group} - -"
        "d ${cfg.state-directory}/sieves 0750 ${config.services.dovecot2.user} ${config.services.dovecot2.group} - -"
      ];

      # Prometheus exporter must start after Dovecot is ready
      services = {
        prometheus-dovecot-exporter = {
          requires = [ "dovecot2.service" ];
          after = [ "dovecot2.service" ];
        };
      };
    };

    environment = {
      etc."dovecot/conf.d/admin.conf" = {
        source = cfg.admin-conf;
        user = config.services.dovecot2.user;
        mode = "400";
      };

      systemPackages = with pkgs; [ dovecot_pigeonhole dovecot-fts-flatcurve ];
    };

    services = {
      prometheus.exporters.dovecot = {
        enable = true;
        scopes = [ "user" "global" ];
        user = cfg.metrics.user;
        listenAddress = "0.0.0.0";
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
        protocols = [ "sieve" ];

        mailPlugins = {
          globally.enable = [ "old_stats" "fts" "fts_flatcurve" ]
            ++ (optional cfg.quota.enable "quota");
          perProtocol = {
            imap.enable = [ "imap_sieve" "fts" "fts_flatcurve" ]
              ++ (optional cfg.quota.enable "imap_quota");
            lmtp.enable = [ "sieve" "fts" "fts_flatcurve" ]
              ++ (optional cfg.quota.enable "quota");
          };
        };

        imapsieve.mailbox = let
          reportSpam = builtins.toFile "spam.sieve" ''
            require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

            if environment :matches "imap.user" "*" {
              set "username" "''${1}";
            }

            pipe :copy "rspamd_learn_spam" [ "''${username}" ];
          '';
          reportHam = builtins.toFile "ham.sieve" ''
            require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

            if environment :matches "imap.mailbox" "*" {
              set "mailbox" "''${1}";
            }

            if string "''${mailbox}" "Trash" {
              stop;
            }

            if string "''${mailbox}" "Junk" {
              stop;
            }

            if environment :matches "imap.user" "*" {
              set "username" "''${1}";
            }

            pipe :copy "rspamd_learn_ham" [ "''${username}" ];
          '';
        in [
          {
            name = "report-spam";
            causes = [ "COPY" ];
            after = reportSpam;
          }
          {
            name = "report-ham";
            causes = [ "COPY" ];
            after = reportHam;
          }
        ];

        sieve = {
          extensions = [ "fileinto" ];
          globalExtensions =
            [ "vnd.dovecot.pipe" "copy" "imapsieve" "environment" "variables" ];
          scripts = {
            after = builtins.toFile "spam.sieve" ''
              require [ "fileinto" ];

              if header :is "X-Spam" "Yes" {
                fileinto "Junk";
                stop;
              }
            '';
          };
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

          # Merge all dovecot plugin directories into a single directory,
          # since mail_plugin_dir only accepts a single path.
          dovecotPluginDir = pkgs.symlinkJoin {
            name = "dovecot-plugin-dir";
            paths = [
              "${pkgs.dovecot}/lib/dovecot"
              "${pkgs.dovecot_pigeonhole}/lib/dovecot"
              "${pkgs.dovecot-fts-flatcurve}/lib/dovecot"
            ];
          };

          mailUserUid = config.users.users."${cfg.mail-user}".uid;
          mailUserGid = config.users.groups."${cfg.mail-group}".gid;
        in ''
          ## Extra Config

          # Add plugin directories for dovecot_pigeonhole and dovecot-fts-flatcurve
          mail_plugin_dir = ${dovecotPluginDir}

          !include /etc/dovecot/conf.d/admin.conf

          ${lib.optionalString cfg.debug ''
            mail_debug = yes
            auth_debug = yes
            verbose_ssl = yes
          ''}

          # SSL/TLS Configuration: TLSv1.2+ only (RFC 8996, 2021)
          # TLSv1.1 and earlier are deprecated and disabled for security
          ssl_min_protocol = TLSv1.2
          ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
          ssl_prefer_server_ciphers = yes

          plugin {
            fts = flatcurve
            fts_autoindex = yes
            fts_enforced = yes
            fts_autoindex_exclude = \Trash
            fts_autoindex_exclude = \Junk
            fts_decoder = decode2text

            # Flatcurve requires language configuration for stemming
            fts_languages = en
            fts_tokenizers = generic email-address
            fts_tokenizer_generic = algorithm=simple maxlen=30
            fts_tokenizer_email_address = maxlen=100

            ${
              optionalString cfg.quota.enable ''
                # Quota configuration
                quota = maildir:User quota
                quota_rule = *:storage=${cfg.quota.limit}
                quota_rule2 = Trash:storage=+1G
                quota_warning = storage=${
                  toString cfg.quota.warning-threshold
                }%% quota-warning ${toString cfg.quota.warning-threshold} %u
                quota_status_success = DUNNO
                quota_status_nouser = DUNNO
                quota_status_overquota = "552 5.2.2 Mailbox is full"
              ''
            }
          }

          service indexer-worker {
            vsz_limit = 0
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

          service doveadm {
            unix_listener doveadm-server {
              user = ${config.services.dovecot2.user}
              group = ${config.services.dovecot2.group}
            }
            inet_listener {
              port = ${toString cfg.ports.admin}
            }
            ${
              optionalString (!isNull cfg.ports.http-admin) ''
                inet_listener http {
                  port = ${toString cfg.ports.http-admin}
                }
              ''
            }
          }

          plugin {
            sieve_plugins = sieve_imapsieve sieve_extprograms
            sieve = file:${cfg.state-directory}/sieves/%u/scripts;active=${cfg.state-directory}/sieves/%u/active.sieve
            # sieve_default = file:${sieveDirectory}/%u/default.sieve
            sieve_default_name = default
            # From elsewhere to Spam folder
            imapsieve_mailbox1_name = Junk
            imapsieve_mailbox1_causes = COPY
            # imapsieve_mailbox1_before = file:${sieveDirectory}/spam.svbin
            # From Spam folder to elsewhere
            imapsieve_mailbox2_name = *
            imapsieve_mailbox2_from = Junk
            imapsieve_mailbox2_causes = COPY
            # imapsieve_mailbox2_before = file:${sieveDirectory}/ham.svbin

            sieve_pipe_bin_dir = ${pipeBin}/bin
            sieve_global_extensions = +vnd.dovecot.pipe +vnd.dovecot.environment
          }

          service decode2text {
            executable = script ${pkgs.dovecot}/libexec/dovecot/decode2text.sh
            user = ${config.services.dovecot2.user}
            unix_listener decode2text {
              mode = 0666
            }
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
