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

  # `pkgs.dovecot` is 2.4 as of nixpkgs 26.05 and this module still speaks 2.3
  # (see the `package` comment further down), so the server, its Sieve plugin
  # and decode2text all have to come from the 2.3 side of nixpkgs. Note that
  # `pkgs.dovecot_pigeonhole` is the 2.4 build -- 0.5 is the 2.3 one -- while
  # dovecot-fts-flatcurve is already built against dovecot_2_3 upstream, the
  # plugin having moved into Dovecot proper in 2.4.
  dovecotPkg = pkgs.dovecot_2_3;
  pigeonholePkg = pkgs.dovecot_pigeonhole_0_5;

  # `services.dovecot2.user` and `.group` were dropped in the 26.05 module
  # rewrite with no rename left behind (hence the bare "attribute 'user'
  # missing" if you go looking for them). These are the replacements.
  dovecotUser = config.services.dovecot2.settings.default_internal_user;
  dovecotGroup = config.services.dovecot2.settings.default_internal_group;

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

      exemptions = mkOption {
        type = listOf str;
        description = "List of usernames exempt from quota limits.";
        default = [ ];
        example = [ "admin" "niten" ];
      };

      admin-email = mkOption {
        type = nullOr str;
        description =
          "Admin email address to notify when users exceed quota. If null, no notifications sent.";
        default = null;
        example = "admin@example.com";
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

    # A `max-user-connections` option lived here. Nothing consumed it --
    # no mail_max_userip_connections was ever emitted -- so it advertised
    # a limit this module does not impose.

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
        "d ${sieveDirectory} 0750 ${dovecotUser} ${dovecotGroup} - -"
      ];

      # Prometheus exporter must start after Dovecot is ready.
      #
      # The unit is `dovecot.service`, not `dovecot2.service`. Up to and
      # including nixpkgs 25.11 the module carried
      # `aliases = [ "dovecot2.service" ]` so the old name still resolved;
      # 26.05 dropped that alias. A Requires= naming a unit that doesn't
      # exist fails the job, so the exporter could not start at all.
      services = {
        prometheus-dovecot-exporter = {
          requires = [ "dovecot.service" ];
          after = [ "dovecot.service" ];
        };
      };
    };

    environment = {
      etc."dovecot/conf.d/admin.conf" = {
        source = cfg.admin-conf;
        user = dovecotUser;
        mode = "400";
      };

      systemPackages = [ pigeonholePkg pkgs.dovecot-fts-flatcurve ];
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

      dovecot2 = let
        # Add learn_ham & learn_spam to dovecot2 path for use by sieves
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

        # The three Sieve scripts live in ./sieves as real files rather
        # than as heredocs here. They used to be inline, duplicated
        # verbatim by unreferenced copies in that directory -- two sources
        # of truth, one of which nothing read and neither of which could
        # drift visibly. As paths they also stop needing the escape dance
        # that Nix string interpolation forces on Sieve's own ${...}
        # variables.
        reportSpam = ./sieves/spam.sieve;
        reportHam = ./sieves/ham.sieve;
        fileSpam = ./sieves/file-spam.sieve;

        # Wrap decode2text.sh with required utilities
        # The original script needs dirname, grep, and cut which aren't in PATH by default
        wrappedDecode2Text = pkgs.writeShellScript "decode2text-wrapped.sh" ''
          export PATH="${pkgs.coreutils}/bin:${pkgs.gnugrep}/bin:$PATH"
          exec ${dovecotPkg}/libexec/dovecot/decode2text.sh "$@"
        '';

        # Quota warning script - sends alert to admin when user hits quota
        quotaWarningScript = pkgs.writeShellScript "quota-warning" ''
          PERCENT=$1
          USER=$2
          ${optionalString (cfg.quota.admin-email != null) ''
            cat << EOF | ${pkgs.system-sendmail}/bin/sendmail ${cfg.quota.admin-email}
            From: Mail System <postmaster@$(hostname -f)>
            To: Admin <${cfg.quota.admin-email}>
            Subject: Quota warning: $USER at $PERCENT%

            User $USER has exceeded $PERCENT% of their mailbox quota.
            Current mailbox size may be approaching the limit of ${cfg.quota.limit}.

            Please investigate and take appropriate action.
            EOF
          ''}
        '';

        # Userdb override for quota exemptions: one bare entry per exempt
        # user, no fields. These lines only have to MATCH -- the userdb
        # block below carries `override_fields = quota_rule=*:storage=0`,
        # which is what actually applies the exemption (and, being an
        # override, wins over anything written here anyway).
        #
        # They previously carried the rule inline as
        # `${user}::::::quota_rule=*:storage=0`, which was a field short:
        # passwd-file is user:password:uid:gid:gecos:home:shell:extra_fields,
        # so with six colons `quota_rule=*` landed in the SHELL field and
        # only `storage=0` reached extra_fields.
        userdbOverride = pkgs.writeText "dovecot-userdb-override"
          (concatStringsSep "\n" (map (user: "${user}::::::") cfg.quota.exemptions));

        mailUserUid = config.users.users."${cfg.mail-user}".uid;

        # `services.dovecot2.mailboxes` was removed in nixpkgs 26.05, so the
        # namespace it used to generate is assembled here instead. Renders as
        # `mailbox "Junk" { auto = create ... }` inside `namespace inbox`,
        # which is what the old option emitted.
        mailboxSections = mapAttrs' (name: mailbox:
          nameValuePair ''mailbox "${name}"'' ({ auto = mailbox.auto; }
            // (optionalAttrs (mailbox.specialUse != null) {
              special_use = "\\" + mailbox.specialUse;
            }) // (optionalAttrs (mailbox.autoexpunge != null) {
              autoexpunge = mailbox.autoexpunge;
            }))) cfg.mailboxes;

        # What used to be `extraConfig`, also removed in 26.05. It is included
        # rather than translated into `settings` because it is Dovecot 2.3
        # config text and stays that way until the 2.4 migration (TODO #17).
        #
        # NOTE ON ORDERING: `includeFiles` emits its `!include` line BEFORE
        # everything in `settings`, where `extraConfig` used to be appended
        # AFTER. Dovecot's last-assignment-wins means the two halves have
        # swapped precedence, so anything this file sets that the module also
        # sets would now silently lose. Everything that overlapped has been
        # moved onto the module options above -- keep it that way when adding
        # to this file.
        extraConf = pkgs.writeText "dovecot-extra.conf" ''
          ## Extra Config

          !include /etc/dovecot/conf.d/admin.conf

          ${optionalString cfg.debug ''
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
            # Numbered, not repeated: Dovecot does not accumulate repeated
            # keys, so a second plain `fts_autoindex_exclude` overwrote the
            # first and Trash was being indexed after all.
            fts_autoindex_exclude = \Trash
            fts_autoindex_exclude2 = \Junk
            fts_decoder = decode2text

            # Flatcurve requires language configuration for stemming
            fts_languages = en
            fts_tokenizers = generic email-address
            fts_tokenizer_generic = algorithm=simple maxlen=30
            fts_tokenizer_email_address = maxlen=100

            # Sieve. Dovecot merges repeated `plugin` sections, so the
            # three this file used to emit were one section written in
            # three places; they are collected here instead.
            sieve = file:${sieveDirectory}/%u/scripts;active=${sieveDirectory}/%u/active.sieve
            sieve_default_name = default

            # old_stats, which feeds the Prometheus exporter via the
            # `service old-stats` sockets below.
            old_stats_refresh = 30 secs
            old_stats_track_cmds = yes

            ${
              optionalString cfg.quota.enable ''
                # Quota configuration
                quota = maildir:User quota
                quota_rule = *:storage=${cfg.quota.limit}
                quota_rule2 = Trash:storage=+1G
                quota_warning = storage=${
                  toString cfg.quota.warning-threshold
                }%% ${quotaWarningScript} ${toString cfg.quota.warning-threshold} %u
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

          ${optionalString (cfg.quota.enable && cfg.quota.exemptions != [ ]) ''
            # Quota exemptions - checked first for override
            userdb {
              driver = passwd-file
              args = username_format=%n ${userdbOverride}
              override_fields = quota_rule=*:storage=0
              result_success = continue-ok
              result_failure = continue
            }
          ''}

          # All users map to one actual system user
          userdb {
            driver = static
            args = uid=${toString mailUserUid} home=${cfg.mail-directory}/%u
          }

          service imap {
            vsz_limit = 1024M
          }

          service doveadm {
            unix_listener doveadm-server {
              user = ${dovecotUser}
              group = ${dovecotGroup}
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

          service decode2text {
            executable = script ${wrappedDecode2Text}
            user = ${dovecotUser}
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
              user = ${dovecotUser}
              group = ${dovecotGroup}
            }
            fifo_listener old-stats-user {
              mode = 0660
              user = ${dovecotUser}
              group = ${dovecotGroup}
            }
          }
        '';

      in {
        enable = true;

        # Pinned to 2.3 deliberately. nixpkgs 26.05 defaults to Dovecot 2.4,
        # which is not a drop-in: its configuration language changed (%u ->
        # %{user}, mail_location split into mail_driver/mail_path, named
        # passdb/userdb sections, rewritten quota settings), old_stats -- the
        # source of everything under `service old-stats` and the Prometheus
        # exporter -- is gone, and fts-flatcurve does not exist for it (in 2.4
        # full-text search moved into Dovecot proper; nixpkgs even builds
        # dovecot-fts-flatcurve against dovecot_2_3 only). The 26.05 module
        # supports 2.3 as a first-class option, branching on the package
        # version throughout. See TODO.md item 25 for the migration.
        package = dovecotPkg;

        enablePAM = false;
        createMailUser = false;

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

        # These name real mailboxes, not labels: the imapsieve_mailbox<n>_name
        # settings this generates used to be overridden by hand-written ones in
        # extraConfig (which won, being appended last), leaving the generated
        # _after keys pointing at the hand-written mailboxes. Same effective
        # config, said once.
        imapsieve.mailbox = [
          {
            # Anything copied INTO Junk is spam
            name = "Junk";
            causes = [ "COPY" ];
            after = reportSpam;
          }
          {
            # Anything copied OUT of Junk is ham
            name = "*";
            from = "Junk";
            causes = [ "COPY" ];
            after = reportHam;
          }
        ];

        sieve = {
          extensions = [ "fileinto" ];
          # vnd.dovecot.pipe is added by the module itself, because pipeBins
          # is non-empty.
          globalExtensions = [ "vnd.dovecot.environment" ];
          # Replaces the hand-rolled buildEnv + sieve_pipe_bin_dir: the module
          # builds the same link farm and adds sieve_extprograms for us.
          pipeBins = map getExe [ learnHam learnSpam ];
          scripts.after = fileSpam;
        };

        # Everything below was a dedicated option before 26.05 rewrote this
        # module around `settings`: enableImap/enableLmtp/protocols,
        # sslServerCert/sslServerKey, mailLocation, mailUser/mailGroup,
        # mailboxes, and `service auth`, which the old module emitted for us.
        # Dovecot 2.3 spellings throughout, to match the pinned package.
        settings = {
          protocols = [ "imap" "lmtp" "sieve" ];

          mail_location = "maildir:${cfg.mail-directory}/%u/";
          mail_uid = cfg.mail-user;
          mail_gid = cfg.mail-group;

          ssl_cert = "<${cfg.ssl.certificate}";
          ssl_key = "<${cfg.ssl.private-key}";
          disable_plaintext_auth = true;

          # Auth has to start as root to read the LDAP config and the static
          # userdb's uid; the pre-26.05 module emitted this unconditionally.
          service = [{
            _section.name = "auth";
            user = "root";
          }];

          "namespace inbox" = {
            inbox = true;
            separator = ''"/"'';
          } // mailboxSections;
        };

        includeFiles = [ extraConf ];
      };
    };
  };
}
