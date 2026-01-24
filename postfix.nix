{ config, lib, pkgs, ... }:

# Postfix SMTP Server Module
#
# Provides email sending (SMTP) and receiving with comprehensive security:
# - Multi-layer spam/abuse prevention via restrictions
# - TLS encryption for all connections (mandatory for submission)
# - SASL authentication via Dovecot for outbound mail
# - SPF policy checking for sender verification
# - DKIM signing via OpenDKIM milter
# - Rspamd integration for spam/virus filtering
# - Sender login mapping to prevent spoofing
# - DNS blacklist (RBL) support
# - Virtual domain and alias support
#
# Architecture choices:
# - Defense in depth: Multiple restriction layers (sender, relay, recipient, client, HELO)
# - Strong TLS: TLSv1.2+ only, weak ciphers disabled, PFS enforced
# - Sender login maps: Prevent authenticated users from spoofing other addresses
# - Milter protocol: Integration with Rspamd and DKIM for content filtering
# - Header cleanup: Remove sensitive headers from submitted mail
# - LMTP delivery: Handoff to Dovecot for local delivery and Sieve filtering
#
# Security model:
# - Port 25 (SMTP): Accept mail from internet, apply all restrictions
# - Port 587 (Submission): Require auth + TLS, apply sender restrictions
# - Port 465 (Submissions): Require auth + TLS (implicit TLS)
# - Trusted networks: Bypass some restrictions (use carefully!)
#
# Mail flow:
# 1. Client/server connects via SMTP (25/587/465)
# 2. TLS negotiation (required for submission ports)
# 3. SASL authentication (for submission)
# 4. Policy checks (SPF, sender validation, blacklists)
# 5. Milter processing (Rspamd spam check, DKIM signing)
# 6. Delivery via LMTP to Dovecot (local) or SMTP (remote)

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

    policy-spf = {
      enable = mkOption {
        type = bool;
        description = "Enable Sender Policy Framework checking.";
        default = true;
      };

      extra-config = mkOption {
        type = str;
        default = "";
        example = "skip_addresses = 127.0.0.0/8,::ffff:127.0.0.0/104,::1";
        description = "Extra configuration options for policyd-spf.";
      };
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

    rate-limit = {
      enable = mkEnableOption "Enable rate limiting for outbound mail." // {
        default = true;
      };

      message-rate-limit = mkOption {
        type = int;
        description = "Maximum messages per hour per authenticated user.";
        default = 100;
      };

      recipient-rate-limit = mkOption {
        type = int;
        description = "Maximum recipients per hour per authenticated user.";
        default = 200;
      };
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

    ldap-recipient-maps = mkOption {
      type = nullOr str;
      description =
        "Path to Postfix LDAP recipient maps configuration. If null, uses catch-all.";
      default = null;
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
        user = config.services.postfix.user;
        group = config.services.postfix.group;
        listenAddress = "0.0.0.0";
        port = cfg.ports.metrics;
      };

      dovecot2 = {
        enable = true;
        enablePAM = false;
        extraConfig = let
          mailUser = config.services.dovecot2.user;
          mailUserUid = config.users.users."${mailUser}".uid;
        in ''
          # Extra Config
          ${lib.optionalString cfg.debug "auth_debug = yes"}

          # When looking up usernames, just use the name, not the full address
          auth_username_format = %n

          auth_mechanisms = login plain

          passdb {
            driver = ldap
            args = ${cfg.ldap-conf}
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
            idle_kill = 3s
          }
        '';
      };

      postfix = let
        pcreFile = name: "pcre:/var/lib/postfix/conf/${name}";
        mappedFile = name: "hash:/var/lib/postfix/conf/${name}";

        # SENDER RESTRICTIONS: Applied to MAIL FROM for ALL mail
        # Defense against sender spoofing and forged addresses
        # Order matters: evaluated sequentially until match
        sender-restrictions = [
          "check_sender_access ${
            mappedFile "reject_senders"
          }" # Blacklist specific senders
          "reject_sender_login_mismatch" # CRITICAL: Prevent auth users from spoofing others
          "reject_non_fqdn_sender" # Require fully-qualified sender addresses
          "permit_sasl_authenticated" # Allow authenticated users
          "permit_mynetworks" # Allow trusted networks
        ] ++ (map (blacklist: "reject_rbl_client ${blacklist}")
          cfg.blacklist.dns) ++ [ "permit" ];

        # RELAY RESTRICTIONS: Control who can relay mail through server
        # Prevents open relay abuse (critical for preventing spam listing)
        relay-restrictions = [
          "permit_sasl_authenticated" # Auth users can relay
          "permit_mynetworks" # Trusted networks can relay
          "reject_unauth_destination" # Block everything else
          "permit"
        ];

        # RECIPIENT RESTRICTIONS: Applied to RCPT TO
        # Multi-layer defense against spam and abuse
        recipient-restrictions = [
          "check_recipient_access ${mappedFile "reject_recipients"}" # Blacklist
          "reject_unknown_sender_domain" # Sender domain must have valid DNS
          "reject_unknown_recipient_domain" # Recipient domain must have valid DNS
          "permit_sasl_authenticated" # Auth users bypass further checks
          "reject_unauth_pipelining" # Block SMTP pipelining abuse
          ## Not needed, since relay did it already
          # "reject_unauth_destination"
          "reject_invalid_hostname" # Require valid hostnames
          "reject_non_fqdn_hostname"
          "reject_non_fqdn_sender"
          "reject_non_fqdn_recipient"
        ] ++ (optional cfg.policy-spf.enable
          "check_policy_service unix:private/policy-spf") # SPF validation
          ++ (map (blacklist: "reject_rbl_client ${blacklist}")
            cfg.blacklist.dns) # DNS blacklists
          ++ [ "permit_mynetworks" "reject_unauth_destination" "permit" ];

        # CLIENT RESTRICTIONS: Applied to connecting clients
        # Very strict: only auth users and trusted networks allowed
        client-restrictions =
          [ "permit_sasl_authenticated" "permit_mynetworks" "reject" ];

        # HELO RESTRICTIONS: Applied to HELO/EHLO for incoming mail
        # Helps catch spambots with invalid HELO strings
        # Note: reject_unknown_helo_hostname disabled (too many false positives)
        incoming-helo-restrictions = [
          "permit_mynetworks"
          "reject_invalid_hostname"
          "reject_non_fqdn_helo_hostname"
          # "reject_unknown_helo_hostname"  # Disabled: causes legitimate mail rejection
        ] ++ (map (blacklist: "reject_rbl_client ${blacklist}")
          cfg.blacklist.dns) ++ [ "permit" ];

        # HELO RESTRICTIONS: Applied to HELO/EHLO for outgoing mail (submission)
        # More permissive since users are authenticated
        outgoing-helo-restrictions = [
          "permit_mynetworks"
          "reject_invalid_hostname"
          # "reject_unknown_helo_hostname"
          "permit"
        ];

        makeRestrictionsString = lst:
          concatStringsSep "," (map (replaceStrings [ " " ] [ "," ]) lst);

      in {
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
        # useSrs = true;

        # dnsBlacklists = cfg.blacklist.dns;

        mapFiles = let
          writeEntries = filename: entries:
            pkgs.writeText filename (concatStringsSep "\n" entries);
          mkRejectList = entries: map (entry: "${entry} REJECT") entries;
          escapeDot = replaceStrings [ "." ] [ "\\." ];
        in {
          reject_senders = writeEntries "sender_blacklist"
            (mkRejectList cfg.blacklist.senders);
          reject_recipients = writeEntries "recipient_blacklist"
            (mkRejectList cfg.blacklist.recipients);
          virtual_mailbox_map = writeEntries "virtual_mailbox_map"
            (map (domain: "@${domain}  OK") allDomains);
          sender_login_map = let
            defaultMaps =
              map (domain: "/^(.*)@${escapeDot domain}$/  \${1}") allDomains;
            userAliasMaps = concatMapAttrsToList (username: userAliases:
              map (alias: "/^${escapeDot alias}$/  ${username}") userAliases)
              cfg.aliases.user-aliases;
            aliasUserMaps = concatMapAttrsToList (alias: users:
              (map (domain:
                "/^${escapeDot alias}@${escapeDot domain}$/  ${
                  concatStringsSep "," users
                }") allDomains)) cfg.aliases.alias-users;
          in writeEntries "sender_login_maps"
          # NOTE: Order is important! If a name matches `default`, it won't keep going
          (userAliasMaps ++ aliasUserMaps ++ defaultMaps);
        };

        networks = cfg.trusted-networks;

        virtual = let
          mkEmail = domain: user: "${user}@${domain}";
          mkUserAliases = concatMapAttrsToList (user: aliases:
            map (alias: "${alias}  ${mkEmail cfg.domain user}") aliases);
          mkAliasUsers = domains:
            let
              userList = users:
                concatStringsSep "," (map (mkEmail cfg.domain) users);
            in concatMapAttrsToList (alias: users:
              let userEmails = userList users;
              in map (domain: "${mkEmail domain alias}  ${userEmails}")
              domains);
        in concatStringsSep "\n" ((mkUserAliases cfg.aliases.user-aliases)
          ++ (mkAliasUsers allDomains cfg.aliases.alias-users));

        config = {
          # TLS certificate and key configuration
          # Combined cert+key file for both server (smtpd) and client (smtp) operations
          smtpd_tls_chain_files = [ cfg.ssl.private-key cfg.ssl.certificate ];
          smtp_tls_chain_files = [ cfg.ssl.private-key cfg.ssl.certificate ];

          virtual_mailbox_domains = allDomains;
          virtual_mailbox_maps = if cfg.ldap-recipient-maps != null then
            "ldap:${cfg.ldap-recipient-maps}, ${
              mappedFile "virtual_mailbox_map"
            }"
          else
            mappedFile "virtual_mailbox_map";

          virtual_transport = "lmtp:inet:${cfg.lmtp-server.host}:${
              toString cfg.lmtp-server.port
            }";

          message_size_limit = cfg.message-size-limit * 1024 * 1024;

          # Rate Limiting: Prevent abuse from compromised accounts
          # Limits messages and recipients per user per hour
        } // (optionalAttrs cfg.rate-limit.enable {
          # Anvil service tracks connection/rate statistics
          anvil_rate_time_unit = "3600s"; # 1 hour window

          # Message rate: max messages per hour per SASL user
          smtpd_client_message_rate_limit =
            toString cfg.rate-limit.message-rate-limit;

          # Recipient rate: max recipients per hour per SASL user
          smtpd_client_recipient_rate_limit =
            toString cfg.rate-limit.recipient-rate-limit;

          # Connection rate: max connections per minute from same IP
          smtpd_client_connection_rate_limit = "60";

          # Enable per-user tracking for authenticated clients
          smtpd_client_restrictions = "permit_sasl_authenticated, reject";
        }) // {

          # Not used?
          # stmpd_banner = "${cfg.hostname} ESMTP NO UCE";

          # Elliptic curve settings for ECDHE key exchange
          # prime256v1 (P-256) for strong, secp384r1 (P-384) for ultra
          tls_eecdh_strong_curve = "prime256v1";
          tls_eecdh_ultra_curve = "secp384r1";

          # SPF policy service timeout (1 hour)
          policy-spf_time_limit = "3600s";

          # DNS resolution order for remote hosts
          smtp_host_lookup = "dns, native";

          # SASL AUTHENTICATION: Integrate with Dovecot for user auth
          # Used for submission ports (587/465) to verify users before accepting mail
          smtpd_sasl_type = "dovecot";
          smtpd_sasl_path = "/run/dovecot2/auth"; # Unix socket to Dovecot
          smtpd_sasl_auth_enable = "yes";
          smtpd_sasl_local_domain = cfg.sasl-domain;
          smtpd_sasl_authenticated_header = "yes"; # Add auth info to headers

          # Disable anonymous SASL mechanisms (require real credentials)
          smtpd_sasl_security_options = "noanonymous";
          smtpd_sasl_tls_security_options = "noanonymous";

          # SENDER LOGIN MAPS: Map email addresses to authorized users
          # CRITICAL: Prevents authenticated users from sending as other addresses
          # Uses PCRE regex to match user@domain patterns to usernames
          smtpd_sender_login_maps = (pcreFile "sender_login_map");

          # Security: Disable VRFY command (prevents user enumeration)
          disable_vrfy_command = "yes";

          # Support plus-addressing: user+tag@domain -> user@domain
          # Useful for filtering and tracking email sources
          recipient_delimiter = "+";

          # MILTER CONFIGURATION: Content filtering via external services
          # Milter protocol v6 for Rspamd and DKIM integration
          milter_protocol = "6";
          milter_mail_macros =
            "i {mail_addr} {client_addr} {client_name} {auth_type} {auth_authen} {auth_author} {mail_addr} {mail_host} {mail_mailer}";

          # Milters for SMTP (incoming mail)
          # Order: Rspamd first (spam check), then DKIM (signing/verification)
          smtpd_milters = [
            "inet:${cfg.rspamd-server.host}:${toString cfg.rspamd-server.port}"
            "inet:${cfg.dkim-server.host}:${toString cfg.dkim-server.port}"
          ];

          # Milters for non-SMTP (locally generated mail)
          non_smtpd_milters = [
            "inet:${cfg.rspamd-server.host}:${toString cfg.rspamd-server.port}"
            "inet:${cfg.dkim-server.host}:${toString cfg.dkim-server.port}"
          ];

          # Require HELO/EHLO before accepting commands
          smtpd_helo_required = true;

          # Apply restriction policies (defined above)
          smtpd_relay_restrictions = relay-restrictions;
          smtpd_sender_restrictions = sender-restrictions;
          smtpd_recipient_restrictions = recipient-restrictions;
          smtpd_helo_restrictions = incoming-helo-restrictions;

          # TLS SECURITY CONFIGURATION
          # Port 25: TLS optional (may) - can't require it for incoming internet mail
          # Ports 587/465: TLS required (encrypt) - enforced in submissionOptions
          smtpd_tls_security_level = "may";

          # TLS Protocol Configuration
          # Disable obsolete/insecure protocols: SSLv2, SSLv3, TLSv1.0
          # TLS Protocol Configuration: TLSv1.2+ only (RFC 8996, 2021)
          # TLSv1.1 and earlier are deprecated and disabled for security
          smtpd_tls_protocols =
            [ "TLSv1.3" "TLSv1.2" "!TLSv1.1" "!TLSv1" "!SSLv2" "!SSLv3" ];
          smtp_tls_protocols =
            [ "TLSv1.3" "TLSv1.2" "!TLSv1.1" "!TLSv1" "!SSLv2" "!SSLv3" ];
          smtpd_tls_mandatory_protocols =
            [ "TLSv1.3" "TLSv1.2" "!TLSv1.1" "!TLSv1" "!SSLv2" "!SSLv3" ];
          smtp_tls_mandatory_protocols =
            [ "TLSv1.3" "TLSv1.2" "!TLSv1.1" "!TLSv1" "!SSLv2" "!SSLv3" ];

          # Cipher Configuration: Use only "high" security ciphers
          # Excludes weak/broken algorithms and ensures forward secrecy
          smtp_tls_ciphers = "high";
          smtpd_tls_ciphers = "high";
          smtp_tls_mandatory_ciphers = "high";
          smtpd_tls_mandatory_ciphers = "high";

          # Explicitly exclude weak/broken ciphers:
          # - MD5: Broken hash
          # - DES/3DES: Weak encryption
          # - RC4: Broken stream cipher
          # - ADH: Anonymous DH (no authentication)
          # - eNULL/aNULL: No encryption/authentication
          # - SRP/PSD: Rarely used, potential issues
          smtpd_tls_mandatory_exclude_ciphers =
            [ "MD5" "DES" "ADH" "RC4" "PSD" "SRP" "3DES" "eNULL" "aNULL" ];
          smtpd_tls_exclude_ciphers =
            [ "MD5" "DES" "ADH" "RC4" "PSD" "SRP" "3DES" "eNULL" "aNULL" ];
          smtp_tls_mandatory_exclude_ciphers =
            [ "MD5" "DES" "ADH" "RC4" "PSD" "SRP" "3DES" "eNULL" "aNULL" ];
          smtp_tls_exclude_ciphers =
            [ "MD5" "DES" "ADH" "RC4" "PSD" "SRP" "3DES" "eNULL" "aNULL" ];

          # Server chooses cipher order (not client)
          # Ensures strong ciphers are preferred
          tls_preempt_cipherlist = "yes";

          # CRITICAL: Require TLS for authentication (prevent password sniffing)
          smtpd_tls_auth_only = "yes";

          # TLS logging level (1 = log handshake and certificate info)
          smtpd_tls_loglevel = "1";

          # Entropy source for TLS random number generation
          tls_random_source = "dev:/dev/urandom";
        };

        submissionOptions = {
          milter_macro_daemon_name = "ORIGINATING";
          smtpd_helo_required = "yes";
          smtpd_tls_security_level = "encrypt";
          smtpd_sasl_auth_enable = "yes";
          smtpd_sasl_type = "dovecot";
          smtpd_sasl_path = "/run/dovecot2/auth";
          smtpd_sasl_security_options = "noanonymous";
          smtpd_sasl_local_domain = cfg.sasl-domain;
          smtpd_helo_restrictions =
            makeRestrictionsString outgoing-helo-restrictions;
          smtpd_client_restrictions =
            makeRestrictionsString client-restrictions;
          smtpd_sender_restrictions =
            makeRestrictionsString sender-restrictions;
          smtpd_recipient_restrictions =
            makeRestrictionsString recipient-restrictions;
          cleanup_service_name = "submission-header-cleanup";
        };

        submissionsOptions = {
          milter_macro_daemon_name = "ORIGINATING";
          smtpd_helo_required = "yes";
          smtpd_tls_security_level = "encrypt";
          smtpd_sasl_auth_enable = "yes";
          smtpd_sasl_type = "dovecot";
          smtpd_sasl_path = "/run/dovecot2/auth";
          smtpd_sasl_security_options = "noanonymous";
          smtpd_sasl_local_domain = cfg.sasl-domain;
          smtpd_helo_restrictions =
            makeRestrictionsString outgoing-helo-restrictions;
          smtpd_client_restrictions =
            makeRestrictionsString client-restrictions;
          smtpd_sender_restrictions =
            makeRestrictionsString sender-restrictions;
          smtpd_recipient_restrictions =
            makeRestrictionsString recipient-restrictions;
          cleanup_service_name = "submission-header-cleanup";
        };

        masterConfig = {
          # See: http://www.postfix.org/smtp.8.html
          lmtp.args = [ "flags=DO" ];
          policy-spf = let
            policydSpfConfig = pkgs.writeText "policyd-spf.conf"
              (concatStringsSep "\n" ([ cfg.policy-spf.extra-config ]
                ++ (lib.optional cfg.debug ''
                  debugLevel=4
                '')));
          in {
            type = "unix";
            privileged = true;
            chroot = false;
            command = "spawn";
            args = [
              "user=nobody"
              "argv=${pkgs.pypolicyd-spf}/bin/policyd-spf"
              "${policydSpfConfig}"
            ];
          };
          smtp = { args = [ "-v" ]; };
          submission = { args = [ "-v" ]; };
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
          showq = { private = false; };
        };
      };
    };
  };
}
