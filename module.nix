{ config, lib, pkgs, ... }:

let
  cfg = config.services.mail-monitor;

  # Build the mail-monitor package
  mail-monitor = pkgs.callPackage ./package.nix { };
in
{
  options.services.mail-monitor = {
    enable = lib.mkEnableOption "mail server monitoring";

    interval = lib.mkOption {
      type = lib.types.str;
      default = "15min";
      description = ''
        How often to run the monitoring checks.
        Uses systemd timer format (e.g., "15min", "1h", "30s").
      '';
    };

    smtp = {
      host = lib.mkOption {
        type = lib.types.str;
        description = "SMTP server hostname";
        example = "mail.example.com";
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 587;
        description = "SMTP server port (587 for STARTTLS, 465 for implicit TLS)";
      };
    };

    imap = {
      host = lib.mkOption {
        type = lib.types.str;
        description = "IMAP server hostname";
        example = "mail.example.com";
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 993;
        description = "IMAP server port (typically 993 for SSL)";
      };
    };

    credentials = {
      username = lib.mkOption {
        type = lib.types.str;
        description = "Email username for authentication tests";
        example = "monitor@example.com";
      };

      passwordFile = lib.mkOption {
        type = lib.types.path;
        description = ''
          Path to file containing the email password.
          The file should contain only the password with no trailing newline.
        '';
        example = "/run/secrets/mail-monitor-password";
      };
    };

    testRecipient = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Email address to send test emails to.
        If null, uses the same address as credentials.username.
      '';
      example = "monitor@example.com";
    };

    receiveTimeout = lib.mkOption {
      type = lib.types.int;
      default = 60;
      description = ''
        How long (in seconds) to wait for test email delivery.
        If the email isn't received within this time, the test fails.
      '';
    };

    ntfy = {
      enable = lib.mkEnableOption "ntfy.sh notifications" // {
        default = true;
      };

      topic = lib.mkOption {
        type = lib.types.str;
        description = "Ntfy.sh topic name for notifications";
        example = "my-mail-server-alerts";
      };

      server = lib.mkOption {
        type = lib.types.str;
        default = "https://ntfy.sh";
        description = "Ntfy.sh server URL (use custom server if self-hosting)";
      };
    };

    stateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/mail-monitor";
      description = "Directory to store state files (for tracking alert state)";
    };
  };

  config = lib.mkIf cfg.enable {
    # Create the systemd service
    systemd.services.mail-monitor = {
      description = "Mail Server Monitoring";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "oneshot";
        ExecStart = let
          configFile = pkgs.writeText "mail-monitor-config.json" (builtins.toJSON {
            smtp_host = cfg.smtp.host;
            smtp_port = cfg.smtp.port;
            imap_host = cfg.imap.host;
            imap_port = cfg.imap.port;
            username = cfg.credentials.username;
            test_recipient = if cfg.testRecipient != null then cfg.testRecipient else cfg.credentials.username;
            receive_timeout = cfg.receiveTimeout;
            ntfy_topic = lib.optionalString cfg.ntfy.enable cfg.ntfy.topic;
            ntfy_server = cfg.ntfy.server;
            state_file = "${cfg.stateDirectory}/state.json";
          });
        in ''
          ${mail-monitor}/bin/mail-monitor \
            --config ${configFile} \
            --password "$(cat ${cfg.credentials.passwordFile})"
        '';

        # Security hardening
        DynamicUser = false;
        User = "mail-monitor";
        Group = "mail-monitor";
        StateDirectory = "mail-monitor";
        StateDirectoryMode = "0700";

        # Restrict capabilities
        CapabilityBoundingSet = "";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" ];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RemoveIPC = true;
        UMask = "0077";
      };
    };

    # Create the systemd timer
    systemd.timers.mail-monitor = {
      description = "Mail Server Monitoring Timer";
      wantedBy = [ "timers.target" ];

      timerConfig = {
        OnBootSec = "5min";  # First run 5 minutes after boot
        OnUnitActiveSec = cfg.interval;
        Persistent = true;  # Catch up missed runs
      };
    };

    # Create user and group
    users.users.mail-monitor = {
      isSystemUser = true;
      group = "mail-monitor";
      description = "Mail monitoring service user";
    };

    users.groups.mail-monitor = { };
  };
}
