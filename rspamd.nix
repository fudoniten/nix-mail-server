{ config, lib, pkgs, ... }:

# Rspamd Spam Filtering Module
#
# Provides advanced spam and malware detection using multiple techniques:
# - Bayesian spam classification with auto-learning
# - DNS blacklist (RBL/DNSBL) checking via SURBL/URIBL
# - SPF/DKIM/DMARC validation
# - Virus scanning via ClamAV integration
# - Greylisting capabilities (when enabled)
# - Neural network classification
# - Phishing detection and URL analysis
# - Sender/IP reputation scoring
#
# Architecture choices:
# - Redis backend for statistics and fuzzy hashes (fast, scalable)
# - Vectorscan/Hyperscan optional (see the `hyperscan` option: it needs SSE4.2+,
#   which pre-Nehalem CPUs such as the Xeon L5420 don't have)
# - Auto-learning via Sieve scripts (ham.sieve/spam.sieve in Dovecot)
# - Milter integration with Postfix for real-time filtering
# - ClamAV rejects infected mail immediately (no quarantine)
# - MX validation checks sender domains have valid mail servers
#
# TODO: Add support for custom DNS blacklists configuration

with lib;
let cfg = config.fudo.mail.rspamd;

in {
  options.fudo.mail.rspamd = with types; {
    enable = mkEnableOption "Enable rspamd spam test server.";

    ports = {
      controller = mkOption {
        type = port;
        default = 11334;
      };
      milter = mkOption {
        type = port;
        default = 11335;
      };
    };

    antivirus = {
      host = mkOption {
        type = str;
        description = "Host of the ClamAV server.";
      };

      port = mkOption {
        type = port;
        description = "Port at which to reach ClamAV";
      };
    };

    redis = {
      host = mkOption {
        type = str;
        default = "redis";
      };

      port = mkOption {
        type = port;
        default = 6379;
      };

      password = mkOption {
        type = nullOr str;
        default = null;
        description = ''
          Password with which to connect to Redis, as a literal value
          baked into the Nix store. Mutually exclusive with password-file;
          prefer that when the password comes from a runtime secrets
          store (Aegis, etc.) rather than something safe to embed in the
          store.
        '';
      };

      password-file = mkOption {
        type = nullOr str;
        default = null;
        description = ''
          Path to a file containing the Redis password, read at start-up
          rather than embedded in the Nix store. Mutually exclusive with
          password.
        '';
      };
    };

    hyperscan = mkOption {
      type = bool;
      default = true;
      description = ''
        Build rspamd with hyperscan (vectorscan) regex acceleration.

        Vectorscan's x86_64 baseline needs SSE4.2 + POPCNT -- even the
        FAT_RUNTIME "generic" tier -- so on pre-Nehalem CPUs an rspamd
        built with it dies with SIGILL the first time it compiles a regex
        cache. Set this false there; rspamd falls back to PCRE matching,
        which is slower but runs anywhere.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [{
      assertion = (cfg.redis.password == null) != (cfg.redis.password-file
        == null);
      message = ''
        fudo.mail.rspamd.redis: set exactly one of password (a literal
        value) or password-file (a runtime path) -- not both, or neither.
      '';
    }];

    # rspamd merges every file under local.d/ (which is what `locals`
    # writes into) at its own start-up, so the password can be handed to
    # it as a SEPARATE file from the one `locals."redis.conf"` manages --
    # written by a plain systemd unit that reads the runtime path when the
    # service actually starts, rather than baked into the Nix-managed
    # config file at eval time the way it used to be. No ConditionPathExists:
    # a skipped unit counts as satisfied, so rspamd would start anyway and
    # fail to authenticate to Redis with a far less obvious error.
    systemd.services.rspamd-redis-password = mkIf (cfg.redis.password-file
      != null) {
      description = "Assemble rspamd's Redis password from its runtime secret.";
      wantedBy = [ "multi-user.target" ];
      before = [ "rspamd.service" ];
      requiredBy = [ "rspamd.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeShellScript "rspamd-redis-password" ''
          set -euo pipefail
          umask 077
          install -d -m 0755 /etc/rspamd/local.d
          PASSWORD="$(cat ${escapeShellArg cfg.redis.password-file})"
          printf 'password = "%s";\n' "$PASSWORD" \
            > /etc/rspamd/local.d/redis-password.conf
          chmod 0644 /etc/rspamd/local.d/redis-password.conf
        '';
      };
    };

    services = {
      # Prometheus metrics are exposed by rspamd itself via the controller
      # worker's native /metrics endpoint (OpenMetrics format), reachable at
      # http://<host>:${toString cfg.ports.controller}/metrics.
      #
      # The old `services.prometheus.exporters.rspamd` option was removed from
      # nixpkgs -- it merely scraped the controller's /stat endpoint, which the
      # built-in /metrics endpoint now replaces. See:
      # https://docs.rspamd.com/developers/protocol#controller-http-endpoints
      rspamd = {
        enable = true;

        # Vectorscan (the hyperscan fork nixpkgs builds rspamd against) needs
        # SSE4.2 + POPCNT as its x86_64 baseline -- even the FAT_RUNTIME
        # "generic" tier -- so on a pre-Nehalem CPU rspamd dies with
        # "Illegal instruction". `hyperscan = false` rebuilds it without,
        # falling back to PCRE regex matching: slower, but it runs.
        #
        # Done with overrideAttrs rather than an override argument because
        # nixpkgs 26.05 dropped rspamd's withVectorscan/withHyperscan flags
        # (it now hardcodes -DENABLE_HYPERSCAN=ON and an unconditional
        # vectorscan buildInput), so there is nothing left to `.override`.
        # ENABLE_HYPERSCAN is still an upstream cmake option, and defaults
        # to OFF there, so this is a configuration rspamd supports: every
        # WITH_HYPERSCAN-guarded entry point has a non-hyperscan stub as of
        # 4.0.x, including the one that was missing in 3.13 (upstream issue
        # #5620, fixed in 98e731bf -- the patch this used to carry, now
        # upstream and dropped).
        package = if cfg.hyperscan then
          pkgs.rspamd
        else
          pkgs.rspamd.overrideAttrs (old: {
            buildInputs =
              filter (dep: (dep.pname or "") != "vectorscan") old.buildInputs;
            cmakeFlags =
              (filter (f: !(hasPrefix "-DENABLE_HYPERSCAN=" f)) old.cmakeFlags)
              ++ [ "-DENABLE_HYPERSCAN=OFF" ];
          });

        locals = {
          # Add detailed spam headers to help with debugging and filtering.
          # Headers include scores, symbols matched, and individual results.
          #
          # skip_authenticated/skip_local keep them off mail this server
          # SENDS: submission runs through the same milter, so without
          # these every outgoing message carried X-Spamd-Result with the
          # internal symbol names and scores -- and the DKIM milter, which
          # runs after rspamd, then signed them.
          "milter_headers.conf".text = ''
            extended_spam_headers = true;
            skip_authenticated = true;
            skip_local = true;
          '';

          # Redis for Bayes statistics, neural network, and reputation data.
          # Redis provides fast, persistent storage for learning and scoring.
          #
          # The password is deliberately NOT set here when password-file is
          # used: rspamd merges every file under local.d/ at its own
          # start-up, and systemd.services.rspamd-redis-password (below)
          # writes a second one, redis-password.conf, from the runtime
          # secret when it's actually available -- not baked into this
          # Nix-store-embedded file at eval time.
          "redis.conf".text = ''
            servers = "${cfg.redis.host}:${toString cfg.redis.port}";
          '' + optionalString (cfg.redis.password != null) ''
            password = "${cfg.redis.password}";
          '';

          # ClamAV integration for virus scanning
          # Action: reject - infected mail is rejected at SMTP time
          # scan_mime_parts: false - scan entire message as one unit for better detection
          "antivirus.conf".text = ''
            clamav {
              action = "reject";
              symbol = "CLAM_VIRUS";
              type = "clamav";
              log_clean = true;
              servers = "${cfg.antivirus.host}:${toString cfg.antivirus.port}";
              scan_mime_parts = false; # scan mail as a whole unit, not parts. seems to be needed to work at all
            }
          '';

          # Neural network for spam detection (requires training data in Redis)
          # Learns patterns from ham/spam classifications over time
          # Higher weights mean stronger signal (3.0 spam, -3.0 ham)
          "neural.conf".text = ''
            symbols = {
              "NEURAL_SPAM" = {
                weight = 3.0;
                description = "Neural network spam";
              }
              "NEURAL_HAM" = {
                weight = -3.0;
                description = "Neural network ham";
              }
            }
          '';

          # MX Check: Verify sender domains have valid mail servers
          # Helps catch forged/spoofed sender addresses
          # Excludes freemail/disposable providers (they have special handling)
          "mx_check.conf".text = ''
            enabled = true;

            timeout = 10.0;

            exclude_domains = [
              "https://maps.rspamd.com/freemail/disposable.txt.zst",
              "https://maps.rspamd.com/freemail/free.txt.zst",
            ];
          '';

          # DMARC policy checking and reporting
          # Validates sender authentication (SPF + DKIM alignment)
          # Applies domain's published DMARC policy (none/quarantine/reject)
          # Stores results in Redis for aggregate report generation
          "dmarc.conf".text = ''
            # Enable DMARC checking
            enabled = true;

            # Aggregate reporting to domain owners: OFF, honestly.
            #
            # This was `enabled = true` with email = postmaster@localhost
            # and no org_name -- which sent nothing regardless, because
            # rspamd only emits aggregate reports when the
            # rspamd_dmarc_report tool is run on a schedule, and there is
            # no such timer here. Turning it on for real means a real
            # org_name/domain/email plus a systemd timer running
            # `rspamd_dmarc_report`; until then, saying false is accurate.
            reporting {
              enabled = false;
            }

            # Actions based on DMARC policy
            # These override the domain's policy for testing
            # Comment out to use domain's published policy
            # actions = {
            #   quarantine = "add_header";
            #   reject = "reject";
            # };
          '';

          # Reputation scoring based on historical data
          # Tracks IP, SPF, DKIM, and generic reputation in Redis
          # Improves scoring accuracy over time as data accumulates
          "reputation.conf".text = ''
            rules {
              ip_reputation = {
                selector "ip" {
                }
                symbol = "IP_REPUTATION";
              }
              spf_reputation =  {
                selector "spf" {
                }
                symbol = "SPF_REPUTATION";
              }
              dkim_reputation =  {
                selector "dkim" {
                }
                symbol = "DKIM_REPUTATION"; # Also adjusts scores for DKIM_ALLOW, DKIM_REJECT
              }
              dmarc_reputation = {
                selector "dmarc" {
                }
                symbol = "DMARC_REPUTATION";
              }
              generic_reputation =  {
                selector "generic" {
                  selector = "ip"; # see https://rspamd.com/doc/configuration/selectors.html
                }
                symbol = "GENERIC_REPUTATION";
              }
            }
          '';

          # A "metrics_exporter.conf" pointing rspamd's graphite backend at
          # a graphite server that does not exist used to sit here. Dead
          # since metrics moved to the controller's native /metrics
          # endpoint (see the comment above `rspamd =`); all it did was
          # make rspamd periodically try to export somewhere.


          # SURBL/URIBL: DNS-based blacklists for URLs in email
          # Checks all URLs (including those in email addresses and DKIM signatures)
          # against multiple reputation databases:
          # - SURBL: Spam URLs
          # - URIBL: Malicious URLs
          # - DBL (Spamhaus): Domain blacklist for spam/phish/malware
          # - RSPAMD_URIBL: Rspamd's own URL reputation database
          # - SEM_URIBL: SpamEatingMonkey URL blacklist
          "rbl.conf".text = ''
            surbl {
              rules {
                "SURBL_MULTI" {
                  ignore_defaults = true; # for compatibility with old defaults
                  rbl = "multi.surbl.org";
                  checks = ['emails', 'dkim', 'urls'];
                  emails_domainonly = true;
                  urls = true;

                  returnbits = {
                    CRACKED_SURBL = 128; # From February 2016
                    ABUSE_SURBL = 64;
                    MW_SURBL_MULTI = 16;
                    PH_SURBL_MULTI = 8;
                    SURBL_BLOCKED = 1;
                  }
                }

                "URIBL_MULTI" {
                  ignore_defaults = true; # for compatibility with old defaults
                  rbl = "multi.uribl.com";
                  checks = ['emails', 'dkim', 'urls'];
                  emails_domainonly = true;

                  returnbits = {
                    URIBL_BLOCKED = 1;
                    URIBL_BLACK = 2;
                    URIBL_GREY = 4;
                    URIBL_RED = 8;
                  }
                }

                "RSPAMD_URIBL" {
                  ignore_defaults = true; # for compatibility with old defaults
                  rbl = "uribl.rspamd.com";
                  checks = ['emails', 'dkim', 'urls'];
                  # Also check images
                  images = true;
                  # Check emails for URLs
                  emails_domainonly = true;
                  # Hashed BL
                  hash = 'blake2';
                  hash_len = 32;
                  hash_format = 'base32';

                  returncodes = {
                    RSPAMD_URIBL = [
                      "127.0.0.2",
                    ];
                  }
                }

                "DBL" {
                  ignore_defaults = true; # for compatibility with old defaults
                  rbl = "dbl.spamhaus.org";
                  no_ip = true;
                  checks = ['emails', 'dkim', 'urls'];
                  emails_domainonly = true;

                  returncodes = {
                    # spam domain
                    DBL_SPAM = "127.0.1.2";
                    # phish domain
                    DBL_PHISH = "127.0.1.4";
                    # malware domain
                    DBL_MALWARE = "127.0.1.5";
                    # botnet C&C domain
                    DBL_BOTNET = "127.0.1.6";
                    # abused legit spam
                    DBL_ABUSE = "127.0.1.102";
                    # abused spammed redirector domain
                    DBL_ABUSE_REDIR = "127.0.1.103";
                    # abused legit phish
                    DBL_ABUSE_PHISH = "127.0.1.104";
                    # abused legit malware
                    DBL_ABUSE_MALWARE = "127.0.1.105";
                    # abused legit botnet C&C
                    DBL_ABUSE_BOTNET = "127.0.1.106";
                    # error - IP queries prohibited!
                    DBL_PROHIBIT = "127.0.1.255";
                    # issue #3074
                    DBL_BLOCKED_OPENRESOLVER = "127.255.255.254";
                    DBL_BLOCKED = "127.255.255.255";
                  }
                }

                "SEM_URIBL_UNKNOWN" {
                  ignore_defaults = true; # for compatibility with old defaults
                  rbl = "uribl.spameatingmonkey.net";
                  no_ip = true;
                  checks = ['emails', 'dkim', 'urls'];
                  emails_domainonly = true;
                  returnbits {
                    SEM_URIBL = 2;
                  }
                }
              }
            }
          '';
        };

        # `overrides."milter_headers.conf"` used to sit here restating
        # extended_spam_headers with the other boolean spelling. It won,
        # being an override, so the local above was dead. Said once now.

        # Worker processes for handling different types of requests
        workers = {
          # Proxy worker: Handles milter protocol for Postfix integration
          # Receives mail from Postfix, scans it, returns verdict
          # 4 workers for parallel processing of incoming mail
          rspamd_proxy = {
            type = "rspamd_proxy";
            bindSockets = [ "*:${toString cfg.ports.milter}" ];
            count = 4;
            extraConfig = ''
              milter = yes;
              timeout = 120s;

              upstream "local" {
                default = yes;
                self_scan = yes;
              }
            '';
          };

          # Controller worker: Provides web UI and API for management
          # Used for training, statistics viewing, and configuration.
          # One process: this is the endpoint that WRITES -- learn requests
          # from the Sieve pipes, statistics, the /metrics scrape -- and
          # fanning that across four workers buys nothing while making
          # concurrent Bayes updates race each other.
          controller = {
            type = "controller";
            count = 1;
            bindSockets = [ "*:${toString cfg.ports.controller}" ];
            includes = [ ];
          };
        };
      };
    };
  };
}
