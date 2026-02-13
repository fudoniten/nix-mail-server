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
# - Vectorscan/Hyperscan disabled (requires SSE4.2+, not available on Xeon L5420)
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
      metrics = mkOption {
        type = port;
        default = 7573;
      };
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
        type = str;
        description = "Password with which to connect to Redis.";
      };
    };
  };

  config = mkIf cfg.enable {
    services = {
      # Prometheus exporter for monitoring spam filtering metrics
      prometheus.exporters.rspamd = {
        enable = true;
        port = cfg.ports.metrics;
        extraLabels = { host = cfg.antivirus.host; };
      };

      rspamd = {
        enable = true;

        # Disable vectorscan (hyperscan fork) to avoid "Illegal instruction"
        # crashes on CPUs without SSE4.2 (e.g. Xeon L5420, which only has SSSE3).
        # Vectorscan's minimum x86_64 requirement is SSE4.2 + POPCNT, regardless
        # of FAT_RUNTIME or AVX2/AVX512 build flags -- the base code tier always
        # uses SSE4.2 instructions.  Rspamd falls back to PCRE regex matching.
        # Note: nixpkgs hardcodes -DENABLE_HYPERSCAN=ON in cmakeFlags, so we
        # must also override that via overrideAttrs.
        package = (pkgs.rspamd.override { withVectorscan = false; }).overrideAttrs
          (old: {
            cmakeFlags = map
              (f:
                if f == "-DENABLE_HYPERSCAN=ON" then
                  "-DENABLE_HYPERSCAN=OFF"
                else
                  f)
              old.cmakeFlags;
          });

        locals = {
          # Add detailed spam headers to help with debugging and filtering
          # Headers include scores, symbols matched, and individual test results
          "milter_headers.conf".text = "extended_spam_headers = yes;";

          # Redis for Bayes statistics, neural network, and reputation data
          # Redis provides fast, persistent storage for learning and scoring
          # WARNING: Password is embedded in Nix store (world-readable)
          # TODO: Use runtime secret injection instead
          "redis.conf".text = ''
            servers = "${cfg.redis.host}:${toString cfg.redis.port}";
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

            # Report to domain owners (aggregate reports)
            reporting = {
              enabled = true;
              email = "postmaster@localhost";
              # org_name = "Your Organization";
              # domain = "example.com";
            };

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

          "metrics_exporter.conf".text = ''
            backend = "graphite";
            metrics = [
              "actions.add header",
              "actions.greylist",
              "actions.reject",
              "actions.rewrite subject",
              "actions.soft reject",
              "connections",
              "ham_count",
              "spam_count",
              "learned",
              "scanned",
            ];
          '';

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

        overrides."milter_headers.conf".text = "extended_spam_headers = true;";

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
          # Used for training, statistics viewing, and configuration
          controller = {
            type = "controller";
            count = 4;
            bindSockets = [ "*:${toString cfg.ports.controller}" ];
            includes = [ ];
          };
        };
      };
    };
  };
}
