{ config, lib, pkgs, ... }:

# TODO: use blacklists

with lib;
let
  cfg = config.fudo.mail.rspamd;
  mailCfg = config.fudo.mail;

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
      prometheus.exporters.rspamd = {
        enable = true;
        port = cfg.ports.metrics;
        extraLabels = { host = cfg.antivirus.host; };
      };

      rspamd = {
        enable = true;

        locals = {
          "disable-hyperscan.conf".text = "disable_hyperscan = true;";

          "milter_headers.conf".text = "extended_spam_headers = yes;";

          "redis.conf".text = ''
            servers = "${cfg.redis.host}:${toString cfg.redis.port}";
            password = "${cfg.redis.password}";
          '';

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

          "mx_check.conf".text = ''
            enabled = true;

            timeout = 10.0;

            exclude_domains = [
              "https://maps.rspamd.com/freemail/disposable.txt.zst",
              "https://maps.rspamd.com/freemail/free.txt.zst",
            ];
          '';

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

          # SURBL checks URLs in emails against known-bad urls
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

        workers = {
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
