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
# - Quota support implemented (fudo.mail.dovecot.quota), with per-user
#   exemptions via a passwd-file userdb consulted ahead of the static one
#
# Mail flow:
# 1. Postfix accepts mail via SMTP
# 2. Mail passes through Rspamd for spam/virus checking
# 3. Postfix delivers to Dovecot via LMTP
# 4. Dovecot applies Sieve filters (spam learning, sorting)
# 5. Mail stored in Maildir format
# 6. Users access via IMAP
#
# Spam learning flow (see ./sieves):
# - User moves mail INTO Junk   -> spam.sieve -> rspamc learn_spam
# - User moves mail OUT of Junk -> ham.sieve  -> rspamc learn_ham

with lib;
let
  cfg = config.fudo.mail.dovecot;

  sieveDirectory = "${cfg.state-directory}/sieves";
  sieveBinDirectory = "${cfg.state-directory}/sieve-bin";


  # Dovecot 2.4 and its matching Pigeonhole. Named explicitly rather than
  # left to the module's default, which picks 2.3 for any system whose
  # stateVersion predates 26.05 -- these containers' included.
  dovecotPkg = pkgs.dovecot;
  pigeonholePkg = pkgs.dovecot_pigeonhole;

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
      description = ''
        Path to a file of Dovecot LDAP settings (`ldap_uris`,
        `passdb_ldap_bind`, ...), included inside `passdb ldap { }`.
      '';
    };

    admin-conf = mkOption {
      type = str;
      description = "Path to admin dovecot2 configuration.";
    };

    oauth2-conf = mkOption {
      type = nullOr str;
      default = null;
      description = ''
        Path to a file of Dovecot `oauth2_*` settings, included at the top
        level of the config. When set, Dovecot also
        accepts OAuth2 bearer tokens (XOAUTH2 / OAUTHBEARER), validated
        against the identity provider, and the LDAP passdb is limited to
        the PLAIN and LOGIN mechanisms. Password logins are unchanged.
      '';
    };
  };


  config = mkIf cfg.enable {
    # User and group for mail storage
    # IMPORTANT: Hardcoded UID/GID 5025 for consistency across systems
    # This ensures mail file ownership remains stable when sharing storage
    # or restoring from backups. Document this requirement for deployments.
    users = {
      users."${cfg.mail-user}" = {
        isSystemUser = true;
        group = cfg.mail-group;
        uid = 5025; # Hardcoded for cross-system consistency
      };
      groups."${cfg.mail-group}" = {
        members = [ cfg.mail-user ];
        gid = 5025; # Hardcoded for cross-system consistency
      };
    };

    systemd = {
      # Directory structure:
      # - state-directory: Dovecot runtime state, indexes, Sieve scripts
      # - mail-directory: Actual mail storage (Maildir format)
      # - sieves: per-user Sieve scripts
      # - sieve-bin: compiled global Sieve scripts. They run as the mail
      #   user, which is who has to be able to write the binaries.
      tmpfiles.rules = [
        "d ${cfg.state-directory}        0711 root root - -"
        "d ${cfg.mail-directory}         0750 ${cfg.mail-user} ${cfg.mail-group} - -"
        "d ${sieveDirectory} 0750 ${dovecotUser} ${dovecotGroup} - -"
        "d ${sieveBinDirectory} 0750 ${cfg.mail-user} ${cfg.mail-group} - -"
      ];
    };

    environment = {
      etc."dovecot/conf.d/admin.conf" = {
        source = cfg.admin-conf;
        user = dovecotUser;
        mode = "400";
      };

      # Pigeonhole has to be on the system path: the module looks for it
      # there, and Dovecot loads its plugins from the system profile.
      # Flatcurve needs nothing here -- it is part of Dovecot as of 2.4.
      systemPackages = [ pigeonholePkg ];
    };

    services.dovecot2 = let
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

      # The three Sieve scripts live in ./sieves as real files rather than
      # as heredocs here. As paths they also stop needing the escape dance
      # that Nix string interpolation forces on Sieve's own ${...}
      # variables.
      reportSpam = ./sieves/spam.sieve;
      reportHam = ./sieves/ham.sieve;
      fileSpam = ./sieves/file-spam.sieve;

      # Attachment decoder for FTS. Dovecot 2.3 shipped an example
      # decode2text.sh that this module used to run; 2.4 no longer installs
      # it. That script called /usr/bin/pdftotext and friends, none of which
      # exist on NixOS, so in practice it only ever handled the zip-based
      # office formats. This keeps those and makes PDF work too.
      decode2text = pkgs.writeShellApplication {
        name = "decode2text";
        runtimeInputs = with pkgs; [ coreutils findutils gawk poppler-utils unzip ];
        text = ''
          content_type="''${1:-}"
          formats='application/pdf pdf
          application/x-pdf pdf
          application/vnd.openxmlformats-officedocument.wordprocessingml.document docx
          application/vnd.openxmlformats-officedocument.spreadsheetml.sheet xlsx
          application/vnd.openxmlformats-officedocument.presentationml.presentation pptx
          application/vnd.oasis.opendocument.text odt
          application/vnd.oasis.opendocument.spreadsheet ods
          application/vnd.oasis.opendocument.presentation odp'

          # Called with no argument, Dovecot asks which types are handled.
          if [ -z "$content_type" ]; then
            echo "$formats"
            exit 0
          fi

          fmt="$(echo "$formats" | awk -v ct="$content_type" '$1 == ct { print $2 }')"
          if [ -z "$fmt" ]; then
            echo "Content-Type: $content_type not supported" >&2
            exit 1
          fi

          tmp="$(mktemp -d)"
          trap 'rm -rf "$tmp"' EXIT
          cat > "$tmp/in"

          xmlunzip() {
            mkdir "$tmp/x"
            unzip -q "$tmp/in" -d "$tmp/x" 2>/dev/null || exit 0
            find "$tmp/x" -name "$1" -print0 | xargs -0 cat \
              | ${dovecotPkg}/libexec/dovecot/xml2text
          }

          export LANG=C.UTF-8
          case "$fmt" in
            pdf) timeout 60 pdftotext -q "$tmp/in" - || true ;;
            odt|ods|odp) xmlunzip content.xml ;;
            docx) xmlunzip document.xml ;;
            xlsx) xmlunzip sharedStrings.xml ;;
            pptx) xmlunzip 'slide*.xml' ;;
          esac
        '';
      };

      # Quota warning script - sends alert to admin when user hits quota.
      #
      # Under 2.3 this never ran: `quota_warning` names a *service* to
      # connect to, and was given this script's store path instead, so
      # every warning was a failed socket connect. It is now a proper
      # `service quota-warning` below.
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
      # section below carries the `quota_storage_size = unlimited` field
      # that actually applies the exemption.
      userdbOverride = pkgs.writeText "dovecot-userdb-override"
        (concatStringsSep "\n" (map (user: "${user}::::::") cfg.quota.exemptions));

      mailUserUid = config.users.users."${cfg.mail-user}".uid;

      globalMailPlugins = {
        fts = true;
        fts_flatcurve = true;
      } // optionalAttrs cfg.quota.enable { quota = true; };

      # `mailbox "Junk" { auto = create ... }` inside `namespace inbox`.
      # Trash and Junk are also kept out of the FTS index (what
      # fts_autoindex_exclude did under 2.3), and Trash gets 1G of quota
      # headroom so a user at the limit can still delete mail.
      mailboxSections = mapAttrs' (name: mailbox:
        nameValuePair ''mailbox "${name}"'' ({ auto = mailbox.auto; }
          // (optionalAttrs (mailbox.specialUse != null) {
            special_use = "\\" + mailbox.specialUse;
          }) // (optionalAttrs (mailbox.autoexpunge != null) {
            autoexpunge = mailbox.autoexpunge;
          }) // (optionalAttrs (elem mailbox.specialUse [ "Trash" "Junk" ]) {
            fts_autoindex = false;
          }) // (optionalAttrs
            (cfg.quota.enable && mailbox.specialUse == "Trash") {
              quota_storage_extra = "1G";
            }))) cfg.mailboxes;

      # Dovecot 2.4 config text. Included rather than spelled as `settings`
      # because most of it is nested sections, which read far better as
      # Dovecot's own syntax.
      #
      # NOTE ON ORDERING: `includeFiles` emits its `!include` line BEFORE
      # everything in `settings`, and Dovecot's last-assignment-wins means
      # anything this file sets that `settings` (or the module) also sets
      # silently loses. Keep the two disjoint. Boolean lists such as
      # `mail_plugins { ... }` are the exception: those merge.
      extraConf = pkgs.writeText "dovecot-extra.conf" ''
        !include /etc/dovecot/conf.d/admin.conf

        ${optionalString cfg.debug ''
          log_debug = category=mail OR category=ssl
          auth_debug = yes
        ''}

        # SSL/TLS Configuration: TLSv1.2+ only (RFC 8996, 2021)
        ssl_server_cert_file = ${cfg.ssl.certificate}
        ssl_server_key_file = ${cfg.ssl.private-key}
        ssl_min_protocol = TLSv1.2
        ssl_cipher_list = HIGH:!aNULL:!MD5:!RC4:!3DES
        ssl_server_prefer_ciphers = server

        mail_driver = maildir
        mail_path = ${cfg.mail-directory}/%{user}
        # 2.3's default for maildir; 2.4 defaults every driver to `fs`,
        # which would make every existing folder invisible.
        mailbox_list_layout = maildir++
        mail_access_groups = ${cfg.mail-group}

        # When looking up usernames, just use the name, not the full address
        auth_username_format = %{user | username}

        ## Full-text search: flatcurve (Xapian), built into Dovecot 2.4.
        fts flatcurve {
        }
        fts_autoindex = yes
        # Fail a search rather than fall back to reading every message when
        # the index is unavailable (2.3's fts_enforced).
        fts_search_read_fallback = no
        fts_decoder_driver = script
        fts_decoder_script_socket_path = decode2text
        language en {
          default = yes
        }
        language_tokenizers = generic email-address
        language_tokenizer_generic_algorithm = simple
        language_tokenizer_generic_token_maxlen = 30
        language_tokenizer_address_token_maxlen = 100

        service indexer-worker {
          vsz_limit = unlimited
        }

        service decode2text {
          executable = script ${getExe decode2text}
          user = ${dovecotUser}
          unix_listener decode2text {
            mode = 0666
          }
        }

        ## Sieve
        # Personal scripts (ManageSieve).
        sieve_script personal {
          driver = file
          path = ${sieveDirectory}/%{user}/scripts
          active_path = ${sieveDirectory}/%{user}/active.sieve
        }
        # Global: file rspamd-flagged spam into Junk, after user scripts.
        sieve_script file-spam {
          type = after
          path = ${fileSpam}
          bin_path = ${sieveBinDirectory}/after
        }

        # Spam learning. Copied INTO Junk is spam; copied OUT of Junk is ham.
        mailbox Junk {
          sieve_script report-spam {
            type = after
            cause = copy
            path = ${reportSpam}
            bin_path = ${sieveBinDirectory}/report-spam
          }
        }
        imapsieve_from Junk {
          sieve_script report-ham {
            type = after
            cause = copy
            path = ${reportHam}
            bin_path = ${sieveBinDirectory}/report-ham
          }
        }

        ${optionalString cfg.quota.enable ''
          ## Quota
          # The size is set at the top level, not inside the quota section,
          # so the exemption userdb's `quota_storage_size` field can override
          # it: userdb fields override top-level settings, not ones nested in
          # a more specific section.
          quota "User quota" {
            warning warn-${toString cfg.quota.warning-threshold} {
              quota_storage_percentage = ${toString cfg.quota.warning-threshold}
              execute quota-warning {
                args = ${toString cfg.quota.warning-threshold} %{user}
              }
            }
          }
          quota_storage_size = ${cfg.quota.limit}

          service quota-warning {
            executable = script ${quotaWarningScript}
            user = ${dovecotUser}
            unix_listener quota-warning {
              user = ${cfg.mail-user}
            }
          }
        ''}

        service lmtp {
          # Enable logging in debug mode
          ${optionalString cfg.debug "executable = lmtp -L"}

          inet_listener dovecot-lmtp {
            listen = 0.0.0.0
            port = ${toString cfg.ports.lmtp}
          }

          ## LMTP has to start as root: it drops privileges after
          ## initialisation, but needs /proc/self/io first.
          ## See: https://dovecot.org/list/dovecot/2019-July/116674.html
          user = root
        }

        ${optionalString (cfg.oauth2-conf != null) ''
          # OAuth2 bearer tokens (webmail SSO). Scoped to the token
          # mechanisms, so a password is never sent to the IdP and a
          # token is never tried as an LDAP password.
          #
          # The oauth2_* settings have to be at the top level: Dovecot's
          # oauth2 initialisation does not see them inside the passdb
          # section ("Missing oauth2_introspection_mode setting").
          !include ${cfg.oauth2-conf}
          passdb oauth2 {
            mechanisms_filter = xoauth2 oauthbearer
          }
        ''}
        passdb ldap {
          ${optionalString (cfg.oauth2-conf != null) "mechanisms_filter = plain login"}
          !include ${cfg.ldap-conf}
        }

        ${optionalString (cfg.quota.enable && cfg.quota.exemptions != [ ]) ''
          # Quota exemptions - checked first for override
          userdb quota-exempt {
            driver = passwd-file
            passwd_file_path = ${userdbOverride}
            fields {
              quota_storage_size = unlimited
            }
            result_success = continue-ok
            result_failure = continue
          }
        ''}

        # All users map to one actual system user.
        #
        # allow_all_users: without it, a static userdb asks the passdbs
        # whether the user exists, and neither can answer -- LDAP binds as
        # the user so it has no lookup without a password, and the
        # mechanisms filters skip both passdbs for a password-less lookup --
        # so every LMTP delivery failed with "User doesn't have home dir
        # set". Postfix already validates recipients against LDAP before
        # handing mail over.
        userdb static {
          static_allow_all_users = yes
          fields {
            uid = ${toString mailUserUid}
            home = ${cfg.mail-directory}/%{user}
          }
        }

        service imap {
          vsz_limit = 1024M
        }

        service doveadm {
          unix_listener doveadm-server {
            user = ${dovecotUser}
            group = ${dovecotGroup}
          }
          inet_listener doveadm {
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

        recipient_delimiter = +
        lmtp_save_to_detail_mailbox = yes
        lda_mailbox_autosubscribe = yes
        lda_mailbox_autocreate = yes

        ## Metrics
        # 2.3's old_stats (and the prometheus-dovecot-exporter that read it)
        # is gone. The stats service serves OpenMetrics directly at
        # http://<host>:${toString cfg.ports.metrics}/metrics, each metric
        # below becoming dovecot_<name>_{count,duration_*}.
        service stats {
          inet_listener http {
            port = ${toString cfg.ports.metrics}
          }
        }
        metric auth_success {
          filter = event=auth_request_finished AND success=yes
        }
        metric auth_failure {
          filter = event=auth_request_finished AND NOT success=yes
        }
        metric imap_command {
          filter = event=imap_command_finished
          group_by cmd_name {
          }
          group_by tagged_reply_state {
          }
        }
        metric mail_delivery {
          filter = event=mail_delivery_finished
        }
        metric smtp_server_transaction {
          filter = event=smtp_server_transaction_finished
        }
        metric login {
          filter = event=auth_client_userdb_lookup_finished
        }
        metric sieve_action {
          filter = event=sieve_action_finished
        }
        metric fts_flatcurve_index {
          filter = event=fts_flatcurve_index
        }
      '';

    in {
      enable = true;
      package = dovecotPkg;

      enablePAM = false;
      createMailUser = false;

      settings = {
        # The configuration syntax this file is written in. Bump it
        # deliberately: it also selects the defaults Dovecot assumes.
        dovecot_config_version = "2.4.5";
        # The oldest Dovecot that must still read what this one writes.
        # 2.3.0 keeps the store readable by the 2.3 build this replaced, so
        # a rollback is just switching back a generation. Raise it to 2.4.0
        # once 2.4 has been running cleanly.
        dovecot_storage_version = "2.3.0";

        protocols = {
          imap = true;
          lmtp = true;
          sieve = true;
        };

        mail_uid = cfg.mail-user;
        mail_gid = cfg.mail-group;

        # A protocol's `mail_plugins` replaces the top-level list rather
        # than adding to it (`doveconf -f protocol=imap -h mail_plugins`
        # shows only what the protocol block names), so each protocol
        # repeats the global ones.
        mail_plugins = globalMailPlugins;
        "protocol imap".mail_plugins = globalMailPlugins // {
          imap_sieve = true;
        } // optionalAttrs cfg.quota.enable { imap_quota = true; };
        "protocol lmtp".mail_plugins = globalMailPlugins // { sieve = true; };

        # imapsieve for the spam-learning scripts; the module adds
        # sieve_extprograms, vnd.dovecot.pipe and sieve_pipe_bin_dir itself,
        # because pipeBins is non-empty.
        sieve_plugins.sieve_imapsieve = true;
        sieve_global_extensions."vnd.dovecot.environment" = true;

        # The module defaults this to plain + login. Adding the token
        # mechanisms only when OAuth2 is configured keeps the non-OAuth
        # config the same as before.
        auth_mechanisms = mkIf (cfg.oauth2-conf != null)
          [ "plain" "login" "xoauth2" "oauthbearer" ];

        # Auth has to start as root to read the LDAP config and the static
        # userdb's uid; the pre-26.05 module emitted this unconditionally.
        service = [{
          _section.name = "auth";
          user = "root";
        }];

        "namespace inbox" = {
          inbox = true;
          separator = "/";
        } // mailboxSections;
      };

      # The rspamd learn commands, for vnd.dovecot.pipe.
      sieve.pipeBins = map getExe [ learnHam learnSpam ];

      includeFiles = [ extraConf ];
    };
  };
}
