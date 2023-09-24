{ config, lib, pkgs, ... }:

with lib;
let
  cfg = config.fudo.mail.postfix;

  allDomains = [ cfg.domain ] ++ cfg.local-domains;

  concatMapAttrsToList = f: as: concatLists (mapAttrsToList f as);

in {
  options.fudo.mail.postfix = with types; {
    enable = mkEnableOption "Enable Postfix SMTP server.";

    debug = mkEnableOption "Enable verbose logging.";

    domain = mkOption {
      type = str;
      description = "Primary domain served by this mail server.";
    };

    local-domains = mkOption {
      type = listOf str;
      description =
        "List of domains to be considered local to this server. Don't include the primary domain.";
      default = [ ];
    };

    hostname = mkOption {
      type = str;
      description = "Fully-qualified hostname of this mail server.";
    };

    trusted-networks = mkOption {
      type = listOf str;
      description = "List of trusted network ranges.";
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
          "Map of username to list of emails belonging to that user.";
        default = { };
        example = { some_user = [ "foo@bar.com" "baz@bar.com" ]; };
      };

      alias-users = mkOption {
        type = attrsOf (listOf str);
        description =
          "Map of aliases to list of accounts which should receive incoming email.";
        default = { };
        example = { hostmaster = [ "admin0" "admin1" ]; };
      };
    };

    ssl = {
      certificate = mkOption {
        type = str;
        description = "Location of host SSL certificate.";
      };

      private-key = mkOption {
        type = str;
        description = "Location of host SSL private key.";
      };
    };

    sasl-domain = mkOption {
      type = str;
      description = "SASL domain to use for authentication.";
    };

    policy-spf.extraConfig = mkOption {
      type = str;
      default = "";
      example = "skip_addresses = 127.0.0.0/8,::ffff:127.0.0.0/104,::1";
      description = "Extra configuration options for policyd-spf.";
    };

    user = mkOption {
      type = str;
      description = "User as which to run Postfix server.";
      default = "postfix";
    };

    group = mkOption {
      type = str;
      description = "Group as which to run Postfix server.";
      default = "postfix";
    };

    message-size-limit = mkOption {
      type = int;
      description = "Max size of email messages, in MB.";
      default = 200;
    };

    ports = {
      metrics = mkOption {
        type = port;
        description = "Port on which to listen for metrics requests.";
        default = 1725;
      };
    };

    ldap-conf = mkOption {
      type = str;
      description = "Path to LDAP dovecot2 configuration.";
    };

    rspamd-server = {
      host = mkOption {
        type = str;
        description = "Hostname of rspamd server.";
      };
      port = mkOption {
        type = port;
        description = "Port on which rspamd is running.";
      };
    };

    lmtp-server = {
      host = mkOption {
        type = str;
        description = "Hostname of lmtp server.";
      };
      port = mkOption {
        type = port;
        description = "Port on which lmtp is running.";
      };
    };

    dkim-server = {
      host = mkOption {
        type = str;
        description = "Hostname of dkim server.";
      };
      port = mkOption {
        type = port;
        description = "Port on which dkim is running.";
      };
    };
  };

  config = mkIf cfg.enable {
    users = {
      users."${cfg.user}" = {
        isSystemUser = true;
        group = cfg.group;
      };

      groups."${cfg.group}".members = [ cfg.user ];
    };

    services = {
      prometheus.exporters.postfix = {
        enable = true;
        systemd.enable = true;
        showqPath = "/var/lib/postfix/queue/public/showq";
        group = config.services.postfix.group;
        listenAddress = "127.0.0.1";
        port = cfg.metrics-port;
      };

      dovecot2 = {
        enable = true;
        enablePAM = false;
        enableImap = false;
        extraConfig = ''
          # Extra Config
          ${lib.optionalString cfg.debug "auth_debug = yes"}

          # When looking up usernames, just use the name, not the full address
          auth_username_format = %n

          auth_mechanisms = login plain

          passdb {
            driver = ldap
            args = ${ldapConfig}
          }

          userdb = {
            driver = ldap
            args = ${ldap-conf}
          }

          service auth {
            unix_listener auth {
              mode = 0600
              user = ${config.services.postfix.user}
              group = ${config.services.postfix.group}
            }
          }

          service auth-worker {
            user = ${config.services.dovecot2.user}
            idle_kill = 3
          }
        '';
      };

      postfix = {
        enable = true;

        user = cfg.user;
        group = cfg.group;

        domain = cfg.domain;
        origin = cfg.domain;
        hostname = cfg.hostname;
        destination = [ "localhost" "localhost.localdomain" ];

        enableHeaderChecks = true;
        enableSmtp = true;
        enableSubmission = true;
        useSrs = true;

        dnsBlacklists = cfg.dns-blacklists;

        mapFiles = let
          writeEntries = filename: entries:
            pkgs.writeText filename (concatStringsSep "\n" entries);
          mkRejectList = entries: map (entry: "${entry} REJECT") entries;
          escapeDot = replaceString [ "." ] [ "\\." ];
        in {
          reject_senders = writeEntries "sender_blacklist"
            (mkRejectList cfg.blacklist.senders);
          reject_recipients = writeEntries "recipient_blacklist"
            (mkRejectList cfg.blacklist.recipients);
          virtual_mailbox_map = writeEntries "virtual_mailbox_map"
            (map (domain: "@${domain}  OK") allDomains);
          sender_login_map = writeEntries "sender_login_maps"
            (map (domain: "/^(.*)@${escapeDot domain}$/  \${1}") allDomains);
        };

        networks = cfg.trusted-networks;

        virtual = let
          mkEmail = domain: user: "${user}@${domain}";
          mkUserAliases = concatMapAttrsToList (user: aliases:
            map (alias: "${alias}  ${mkEmail cfg.domain user}"));
          mkAliasUsers = domains:
            let
              userList = users:
                concatStringsSep "," (map (mkEmail cfg.domain) users);
            in concatMapAttrsToList (alias: users:
              concatMap
              (domain: "${mkEmail domain alias}  ${mkAliasUsers users}"));
        in concatStringsSep "\n" ((mkUserAliases cfg.aliases.user-aliases)
          ++ (mkAliasUsers allDomains cfg.aliases.alias-users));

        sslCert = cfg.ssl.certificate;
        sslKey = cfg.ssl.private-key;

        config = let
          pcreFile = name: "pcre:/var/lib/postfix/conf/${name}";
          mappedFile = name: "hash:/var/lib/postfix/conf/${name}";

          sender-restrictions = [
            "check_sender_access ${mapped-file "reject_senders"}"
            "reject_sender_login_mismatch"
            "reject_non_fqdn_sender"
            "reject_unknown_sender_domain"
            "permit_mynetworks"
            "permit_sasl_authenticated"
          ] ++ (map (blacklist: "reject_rbl_client ${blacklist}")
            cfg.blacklist.dns) ++ [ "reject" ];

          relay-restrictions = [
            "reject_unauth_destination"
            "reject_unauth_pipelining"
            "reject_unauth_destination"
            "reject_unknown_sender_domain"
            "permit_mynetworks"
            "permit_sasl_authenticated"
          ] ++ (map (blacklist: "reject_rbl_client ${blacklist}")
            cfg.blacklist.dns) ++ [ "reject" ];

          recipient-restrictions = [
            "check_sender_access ${mapped-file "reject_recipients"}"
            "reject_unknown_sender_domain"
            "reject_unknown_recipient_domain"
            "reject_unauth_pipelining"
            "reject_unauth_destination"
            "reject_invalid_hostname"
            "reject_non_fqdn_hostname"
            "reject_non_fqdn_sender"
            "reject_non_fqdn_recipient"
            "check_policy_service unix:private/policy-spf"
          ] ++ (map (blacklist: "reject_rbl_client ${blacklist}")
            cfg.blacklist.dns)
            ++ [ "permit_mynetworks" "permit_sasl_authenticated" "reject" ];

          client-restrictions =
            [ "permit_sasl_authenticated" "permit_mynetworks" "reject" ];

          helo-restrictions = [
            "permit_mynetworks"
            "reject_invalid_hostname"
            "reject_non_fqdn_helo_hostname"
            "reject_unknown_helo_hostname"
          ] ++ (map (blacklist: "reject_rbl_client ${blacklist}")
            cfg.blacklist.dns) ++ [ "permit" ];

        in {
          virtual_mailbox_domains = allDomains;
          virtual_mailbox_maps = mappedFile "virtual_mailbox_map";

          ## I don't think these are needed...
          # virtual_uid_maps = let uid = config.users.users."${cfg.user}".uid;
          # in "static:${toString uid}";
          # virtual_gid_maps = let gid = config.users.groups."${cfg.group}".gid;
          # in "static: ${toString gid}";

          virtual_transport =
            "lmtp:inet:${cfg.lmtp-server.host}:${cfg.lmtp-server.port}";

          message_size_limit = toString (cfg.message-size-limit * 1024 * 1024);

          stmpd_banner = "${cfg.hostname} ESMTP NO UCE";

          tls_eecdh_strong_curve = "prime256v1";
          tls_eecdh_ultra_curve = "secp384r1";

          policy-spf_time_limit = "3600s";

          smtp_host_lookup = "dns, native";

          smtpd_sasl_type = "dovecot";
          smtpd_sasl_path = "/run/dovecot2/auth";
          smtpd_sasl_auth_enable = "yes";
          smtpd_sasl_local_domain = cfg.sasl-domain;
          smtp_sasl_authenticated_header = "yes";

          smtpd_sasl_security_options = "noanonymous";
          smtpd_sasl_tls_security_options = "noanonymous";

          smtpd_sender_login_maps = (pcreFile "sender_login_map");

          disable_vrfy_command = "yes";

          recipient_delimiter = "+";

          milter_protocol = "6";
          milter_mail_macros =
            "i {mail_addr} {client_addr} {client_name} {auth_type} {auth_authen} {auth_author} {mail_addr} {mail_host} {mail_mailer}";

          smtpd_milters = [
            "inet:${cfg.rspamd-server.host}:${cfg.rspamd-server.port}"
            "inet:${cfg.dkim.host}:${cfg.dkim.port}"
          ];

          non_smtpd_milters = [
            "inet:${cfg.rspamd-server.host}:${cfg.rspamd-server.port}"
            "inet:${cfg.dkim.host}:${cfg.dkim.port}"
          ];

          helo_required = true;

          smtpd_relay_restrictions = relay-restrictions;

          smtpd_sender_restrictions = sender-restrictions;

          smtpd_recipient_restrictions = recipient-restrictions;

          smtpd_helo_restrictions = helo-restrictions;

          # Handled by submission
          smtpd_tls_security_level = "may";

          smtpd_tls_eecdh_grade = "ultra";

          # Disable obselete protocols
          smtpd_tls_protocols =
            [ "TLSv1.2" "TLSv1.1" "!TLSv1" "!SSLv2" "!SSLv3" ];
          smtp_tls_protocols =
            [ "TLSv1.2" "TLSv1.1" "!TLSv1" "!SSLv2" "!SSLv3" ];
          smtpd_tls_mandatory_protocols =
            [ "TLSv1.2" "TLSv1.1" "!TLSv1" "!SSLv2" "!SSLv3" ];
          smtp_tls_mandatory_protocols =
            [ "TLSv1.2" "TLSv1.1" "!TLSv1" "!SSLv2" "!SSLv3" ];

          smtp_tls_ciphers = "high";
          smtpd_tls_ciphers = "high";
          smtp_tls_mandatory_ciphers = "high";
          smtpd_tls_mandatory_ciphers = "high";

          smtpd_tls_mandatory_exclude_ciphers =
            [ "MD5" "DES" "ADH" "RC4" "PSD" "SRP" "3DES" "eNULL" "aNULL" ];
          smtpd_tls_exclude_ciphers =
            [ "MD5" "DES" "ADH" "RC4" "PSD" "SRP" "3DES" "eNULL" "aNULL" ];
          smtp_tls_mandatory_exclude_ciphers =
            [ "MD5" "DES" "ADH" "RC4" "PSD" "SRP" "3DES" "eNULL" "aNULL" ];
          smtp_tls_exclude_ciphers =
            [ "MD5" "DES" "ADH" "RC4" "PSD" "SRP" "3DES" "eNULL" "aNULL" ];

          tls_preempt_cipherlist = "yes";

          smtpd_tls_auth_only = "yes";

          smtpd_tls_loglevel = "1";

          tls_random_source = "dev:/dev/urandom";
        };

        submissionOptions = {
          smtpd_tls_security_level = "encrypt";
          smtpd_sasl_auth_enable = "yes";
          smtpd_sasl_type = "dovecot";
          smtpd_sasl_path = "/run/dovecot2/auth";
          smtpd_sasl_security_options = "noanonymous";
          smtpd_sasl_local_domain = cfg.domain;
          smtpd_client_restrictions = client-restrictions;
          smtpd_sender_restrictions = sender-restrictions;
          smtpd_recipient_restrictions = recipient-restrictions;
          cleanup_service_name = "submission-header-cleanup";
        };

        masterConfig = {
          # See: http://www.postfix.org/smtp.8.html
          lmtp.args = [ "flags=DO" ];
          policy-spf = let
            policySpfFile = pkgs.writeText "policyd-spf.conf"
              (cfg.postfix.policy-spf.extraConfig
                + (lib.optionalString cfg.debug "debugLevel = 4"));
          in {
            type = "unix";
            privileged = true;
            chroot = false;
            command = "spawn";
            args = [
              "user=nobody"
              "argv=${pkgs.pypolicyd-spf}/bin/policyd-spf"
              "${policydSpf}"
            ];
          };
          submission-header-cleanup = let
            submissionHeaderCleanupRules =
              pkgs.writeText "submission_header_cleanup_rules" ''
                # Removes sensitive headers from mails handed in via the submission port.
                # See https://thomas-leister.de/mailserver-debian-stretch/
                # Uses "pcre" style regex.

                /^Received:/                 IGNORE
                /^X-Originating-IP:/         IGNORE
                /^X-Mailer:/                 IGNORE
                /^User-Agent:/               IGNORE
                /^X-Enigmail:/               IGNORE
                /^Message-ID:\s+<(.*?)@.*?>/ REPLACE Message-ID: <$1@${cfg.hostname}>
              '';
          in {
            type = "unix";
            private = false;
            chroot = false;
            maxproc = 0;
            command = "cleanup";
            args =
              [ "-o" "header_checks=pcre:${submissionHeaderCleanupRules}" ];
          };
        };
      };
    };
  };
}
