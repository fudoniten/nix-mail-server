# TODO & Improvements

## Recently Fixed Issues ✅

### Critical Bug: Group Aliases Malformed [FIXED]

**Status: FIXED** - The `mkAliasUsers` function in `postfix.nix` was generating invalid virtual alias entries.

**Bug**: Line 397 used bare usernames instead of full email addresses for group alias recipients.

**Impact**: Group aliases (e.g., `support@domain` → multiple users) would fail to deliver because Postfix expected full email addresses for virtual mailbox delivery.

**Fix**: Changed `concatStringsSep "," users` to `userList users` to properly format recipient addresses.

---

## Critical Security Issues

### 1. Secrets in Nix Store [PARTIAL]

**Priority: MEDIUM** (was HIGH)

**Status**: the secrets that need external coordination now come from runtime
paths, assembled at start-up by the `mail-secrets` unit rather than baked in at
eval time: `ldap.bind-password-file` and `ldap.outpost-token-file`.

**Still open**: the three internal secrets -- the Dovecot admin password, the
Dovecot doveadm API key, and the Redis password shared with rspamd -- still
default to a value derived deterministically from `build-seed` and stored in the
world-readable Nix store. Each has an `internal-secrets.*-file` option; setting
all three to paths from a real secrets store closes this completely.

The original problem, for reference:

- `rspamd.nix`: Redis password embedded in config
- `mail-server.nix`: LDAP bind password via `readFile`
- Auto-generated passwords for Dovecot admin and API keys

**Impact**: Any user on the system can read these secrets.

**Solution Options**:
1. Use systemd `LoadCredential` for runtime secret injection
2. Use agenix or sops-nix for encrypted secrets in Nix
3. Use external secret management (Vault, etc.)

**Example Fix**:
```nix
# Instead of:
password = "${cfg.redis.password}";

# Use:
systemd.services.rspamd.serviceConfig.LoadCredential = "redis-password:/secrets/redis-password";
# Then read from $CREDENTIALS_DIRECTORY/redis-password in config
```

**Files to Update**:
- `rspamd.nix` - Redis password
- `mail-server.nix` - LDAP password, Dovecot credentials
- All container configurations

---

### 2. No Intrusion Prevention System [PARTIAL -- VERIFY]

**Priority: HIGH**

**Status**: fail2ban is configured, with jails for Postfix SASL and Dovecot
authentication. It is **not confirmed to do anything**, and there are two
concrete reasons to expect it does not:

1. The jails use `backend = "systemd"`, whose filters match
   `_SYSTEMD_UNIT=postfix.service`. Postfix and Dovecot run inside containers,
   so their output reaches the host journal tagged with the container runtime's
   unit and `CONTAINER_NAME` fields instead. The filters will not match.
2. Bans are inserted into `INPUT`. Traffic to published container ports is
   DNAT'd and bypasses that chain -- it would need `DOCKER-USER` or the
   netavark equivalent.

**To verify**: run `fail2ban-client status postfix-sasl` after a period during
which the logs show failed authentications. Zero matches confirms (1).

**If it is broken**, the options are to ship logs out of the containers in a
form the filters recognise and fix the ban chain, or to drop fail2ban and say so
plainly rather than leaving apparent protection in place.

Previously: No fail2ban or similar IPS configured. Mail servers are constantly attacked with brute force attempts on:
- SMTP AUTH (ports 587, 465)
- IMAP/IMAPS (ports 143, 993)
- Dovecot admin interface

**Impact**: Account compromise via brute force is possible.

**Solution**:
```nix
services.fail2ban = {
  enable = true;
  jails = {
    postfix-sasl = ''
      enabled = true
      filter = postfix-sasl
      port = smtp,submission,submissions
      logpath = %(postfix_log)s
      maxretry = 3
      findtime = 600
      bantime = 3600
    '';
    dovecot = ''
      enabled = true
      filter = dovecot
      port = imap,imaps,pop3,pop3s
      logpath = %(dovecot_log)s
      maxretry = 3
      findtime = 600
      bantime = 3600
    '';
  };
};
```

**Estimated Effort**: 2-4 hours

---

### 3. No DMARC Support [COMPLETED ✅]

**Priority: MEDIUM-HIGH**

**Status: COMPLETED** - DMARC checking is now enabled in rspamd with reporting capabilities.

Previously: SPF and DKIM are configured, but DMARC checking is missing. DMARC provides:
- Policy enforcement for SPF/DKIM alignment
- Reporting on authentication failures
- Better protection against spoofing

**Impact**: Missing part of modern email authentication trinity (SPF + DKIM + DMARC).

**Solution**: Add DMARC checking to Rspamd (already has built-in support):
```nix
# rspamd.nix
"dmarc.conf".text = ''
  enabled = true;
  reporting {
    enabled = true;
    email = "postmaster@${cfg.primary-domain}";
    from_name = "DMARC Report";
  }
'';
```

**Estimated Effort**: 1-2 hours

---

## Critical Operational Issues

### 4. No Backup Strategy

**Priority: CRITICAL**

No backup configuration or documentation for critical data. Everything lives
under `state-directory` on the host -- these are NOT the in-container paths,
which is what this item used to list:

| Path (with `state-directory = /var/lib/mail`) | Loss means |
| --- | --- |
| `/var/lib/mail/mail` | Unrecoverable. User mailboxes. |
| `/var/lib/mail/dkim` | Republish DNS, plus a window of failed verification. |
| `/var/lib/mail/redis` | Weeks of accumulated spam training. |
| `/var/lib/mail/dovecot` | Recoverable -- indexes and Sieve scripts rebuild. |
| `/var/lib/mail/postfix` | Queued mail in flight at backup time. |
| `/var/lib/mail/antivirus` | Nothing; freshclam re-fetches. |

**Impact**: Data loss in case of hardware failure or corruption.

**Solution Options**:

1. **Add backup module**:
```nix
services.restic.backups.mail = {
  repository = "s3:bucket/mail-backups";
  paths = [
    "/var/lib/mail/mail"
    "/var/lib/mail/dkim"
    "/var/lib/mail/redis"
  ];
  timerConfig = {
    OnCalendar = "daily";
  };
  exclude = [
    "/var/lib/mail/mail/*/.Trash"
    "/var/lib/mail/mail/*/.Junk"
  ];
};
```

Note Redis should be snapshotted while consistent -- a plain file copy of a
live `dump.rdb` can be torn.

2. **Document backup procedures** in README
3. **Add restore testing** to maintenance schedule

**Estimated Effort**: 4-8 hours (including testing)

---

### 5. No Log Retention/Aggregation

**Priority: MEDIUM**

Logs are in journald with default retention. No centralized logging or defined retention policies.

**Impact**:
- Difficult to debug historical issues
- No correlation across services
- Logs may be lost on disk space issues

**Solution**:
```nix
services.promtail = {
  enable = true;
  configuration = {
    server = {
      http_listen_port = 28183;
    };
    clients = [{
      url = "http://loki:3100/loki/api/v1/push";
    }];
    scrape_configs = [{
      job_name = "mail";
      journal = {
        max_age = "12h";
        labels = {
          job = "mail";
          host = config.networking.hostName;
        };
      };
      relabel_configs = [{
        source_labels = ["__journal__systemd_unit"];
        target_label = "unit";
      }];
    }];
  };
};

# Or simpler: just configure journal retention
services.journald.extraConfig = ''
  SystemMaxUse=2G
  MaxRetentionSec=30day
'';
```

**Estimated Effort**: 2-4 hours (journald only) or 8-16 hours (full Loki setup)

---

### 6. No Monitoring Alerts

**Priority: MEDIUM**

Prometheus exporters are configured but no alerts defined.

**Critical alerts needed**:
- Mail queue size > threshold
- Failed delivery rate > threshold
- Disk space < 10%
- Service down (Postfix, Dovecot, Rspamd, ClamAV)
- Certificate expiration < 30 days
- Spam/ham ratio anomalies
- DKIM signing failures

**Solution**:
```nix
# prometheus-alerts.nix
services.prometheus.rules = [{
  name = "mail-alerts";
  rules = [
    {
      alert = "MailQueueHigh";
      expr = "postfix_queue_length > 100";
      for = "5m";
      annotations = {
        summary = "High mail queue on {{ $labels.instance }}";
        description = "{{ $value }} messages in queue";
      };
    }
    {
      alert = "MailServiceDown";
      expr = "up{job=~\"postfix|dovecot|rspamd\"} == 0";
      for = "2m";
      annotations = {
        summary = "Mail service {{ $labels.job }} down";
      };
    }
    # ... more alerts
  ];
}];
```

**Estimated Effort**: 4-8 hours

---

## Missing Features

### 7. No Rate Limiting [COMPLETED ✅]

**Priority: MEDIUM-HIGH**

**Status: COMPLETED** - Rate limiting now configured for messages, recipients, and connections per hour.

Previously: No outbound email rate limiting configured.

**Impact**: If account is compromised, could be used to send spam rapidly, getting the server blacklisted.

**Solution**:
```nix
# postfix.nix - add to config
smtpd_client_message_rate_limit = 100;  # per client IP
smtpd_client_recipient_rate_limit = 100;
smtpd_client_connection_rate_limit = 10;

# Per-user rate limiting (requires policy service)
# Consider policyd-rate-limit or similar
```

**Estimated Effort**: 2-4 hours

---

### 8. No Greylisting

**Priority: LOW-MEDIUM**

Rspamd supports greylisting but it's not enabled. Greylisting is effective against spam but adds delay to first-time senders.

**Trade-off**: Slight delay in delivery (usually 5-15 minutes) vs. significant spam reduction.

**Solution**:
```nix
# rspamd.nix
"greylist.conf".text = ''
  enabled = true;
  timeout = 300;  # 5 minutes
  expire = 86400;  # 1 day
  key_prefix = "greylist";
  message = "Try again later";

  # Whitelist authenticated users
  whitelist_ip = [
    "${concatStringsSep "\", \"" cfg.trusted-networks}"
  ];
'';
```

**Estimated Effort**: 1-2 hours

---

### 9. No Recipient Validation [COMPLETED ✅]

**Priority**: MEDIUM

**Status: COMPLETED** - LDAP recipient validation now configured. Postfix queries LDAP before accepting mail.

Previously: Currently accepts mail for non-existent users, then bounces. Better to reject at SMTP time.

**Impact**:
- Backscatter (bouncing spam to forged senders)
- Wasted resources processing invalid mail
- Helps spammers enumerate valid addresses

**Solution**:
```nix
# postfix.nix - add to config
local_recipient_maps = "ldap:/etc/postfix/ldap-recipients.cf";

# Then create ldap-recipients.cf that queries LDAP for valid users
```

**Estimated Effort**: 2-4 hours

---

### 10. No Mail Quotas [COMPLETED ✅]

**Priority**: LOW-MEDIUM

**Status: COMPLETED** - Mailbox quotas now configured with 10G default limit and 90% warning threshold.

Previously: No per-user quotas configured. Users can fill disk with mail.

**Solution**:
```nix
# dovecot.nix - add to extraConfig
quota = maildir:User quota
quota_rule = *:storage=10G
quota_warning = storage=95%% quota-warning 95 %u
quota_warning2 = storage=80%% quota-warning 80 %u
```

**Estimated Effort**: 2-4 hours (including warning script)

---

### 11. No Automatic Certificate Management

**Priority**: MEDIUM

TLS certificates are manually managed. No integration with ACME/Let's Encrypt auto-renewal.

**Impact**: Manual renewal required, risk of expiration.

**Solution**:
```nix
security.acme.certs."mail.example.com" = {
  domain = "mail.example.com";
  extraDomainNames = [ "smtp.example.com" "imap.example.com" ];
  group = "mail";
  postRun = ''
    systemctl reload postfix
    systemctl reload dovecot2
  '';
};

# Then reference in postfix/dovecot configs
fudo.mail.smtp.ssl-directory = "/var/lib/acme/mail.example.com";
```

**Estimated Effort**: 2-4 hours

---

## Code Quality Issues

### 12. TLSv1.1 Deprecation [COMPLETED ✅]

**Priority**: LOW

**Status: COMPLETED** - TLSv1.1 disabled in both Postfix and Dovecot. TLSv1.2+ only.

Previously: TLSv1.1 is deprecated (RFC 8996, 2021) but still enabled for compatibility.

**Files**: `postfix.nix:490-498`

**Solution**: Remove TLSv1.1 from allowed protocols:
```nix
smtpd_tls_protocols = [ "TLSv1.2" "TLSv1.3" "!TLSv1.1" "!TLSv1" "!SSLv2" "!SSLv3" ];
```

**Risk**: May break compatibility with very old mail clients/servers. Test before deploying.

**Estimated Effort**: 1 hour (plus testing)

---

### 13. Hardcoded UID/GID

**Priority**: DOCUMENTATION

UID/GID 5025 is hardcoded for mail user in `dovecot.nix:228,238`.

**Issue**: Not actually a problem, but needs documentation.

**Status**: ✅ Already documented in code comments and README.md

**Action**: None required.

---

### 14. Missing DNS Documentation

**Priority**: MEDIUM

DNS requirements are scattered or implied, not centrally documented.

**Status**: ✅ Already addressed in README.md

**Action**: None required.

---

## Performance Improvements

### 15. Hyperscan/Vectorscan Configuration (RESOLVED)

**Priority**: COMPLETED

**Status**: Hyperscan/vectorscan is a per-deployment build option, on by default.

**Background**: Vectorscan (the hyperscan fork) requires SSE4.2 + POPCNT as its
minimum x86_64 instruction set -- even the FAT_RUNTIME SSSE3 "baseline" tier uses
SSE4.2 instructions internally. The Xeon L5420 only supports up to SSSE3, so
vectorscan cannot run on this hardware regardless of build flags.

An earlier attempt built vectorscan with FAT_RUNTIME=ON and AVX2/AVX512 disabled,
but this still crashed with "Illegal instruction" because the base code tier
unconditionally uses SSE4.2 instructions (POPCNT, etc.).

**Solution Applied**:
`fudo.mail.antispam.hyperscan` (default true) selects the rspamd build. Set it
false on pre-SSE4.2 hardware and rspamd.nix rebuilds rspamd with
`-DENABLE_HYPERSCAN=OFF` and vectorscan dropped from its buildInputs, falling
back to PCRE-based regex matching -- slower, but functional. Hosts with modern
CPUs get stock `pkgs.rspamd` and pay nothing for this.

Two historical wrinkles, both now resolved upstream: a linker error in rspamd
3.7.x (issue #4701, fixed by d907a95 in 3.13.0) and a missing
`rspamd_re_cache_compile_hyperscan_scoped_single` stub in 3.13 (issue #5620,
fixed by 98e731bf). rspamd 4.0.x carries both, so the fetchpatch this module
used to apply has been dropped. The override is done with `overrideAttrs`
rather than `.override { withVectorscan = false; }` because nixpkgs 26.05
removed rspamd's withVectorscan/withHyperscan arguments.

**Future Optimization**: After upgrading to hardware with SSE4.2+ support,
drop the `fudo.mail.antispam.hyperscan = false` setting from that host's config
to re-enable vectorscan for faster regex matching.

---

### 16. Redis Persistence Configuration [PARTIAL]

**Priority**: LOW

**Status**: the container volume was mounted at `/var/lib/redis` while the NixOS
redis module writes to `/var/lib/redis-rspamd` (it derives the directory from
the server name), so *nothing was persisted at all* -- the entire Bayes corpus,
neural model and reputation data were discarded on every container recreation.
The mount now points at the right path.

**Still open**: save/appendonly policy is whatever Redis defaults to.

**Consideration**: Tune RDB/AOF settings based on mail volume and recovery requirements.

**Solution**:
```nix
# mail-server.nix - redis container
environment.REDIS_SAVE = "900 1 300 10 60 10000";  # RDB snapshots
environment.REDIS_APPENDONLY = "yes";  # AOF for durability
```

**Estimated Effort**: 1-2 hours

---

## Documentation Improvements

### 17. DNS Blacklist Recommendations

**Priority**: LOW

No recommended DNS blacklists documented.

**Recommended RBLs** (add to configuration):
```nix
blacklist.dns = [
  "zen.spamhaus.org"     # Combined Spamhaus lists (highly recommended)
  "bl.spamcop.net"       # SpamCop
  "b.barracudacentral.org"  # Barracuda
  "dnsbl.sorbs.net"      # SORBS (use with caution - aggressive)
];
```

**Caution**: Some RBLs have false positives. Test before production.

**Status**: ✅ Mentioned in README.md

---

### 18. Sieve Scripts Documentation

**Priority**: LOW

Sieve scripts exist (`sieves/ham.sieve`, `sieves/spam.sieve`) but aren't documented.

**Action**: Document in README.md how spam learning works via Sieve.

**Status**: ✅ Already documented in code comments and README.md

---

## Nice-to-Have Features

### 19. Vacation/Autoresponder Support

**Priority**: LOW

No vacation/autoresponder functionality via Sieve.

**Solution**: Add vacation Sieve extension support and UI for users to configure.

**Estimated Effort**: 4-8 hours

---

### 20. Mail Archive for Compliance

**Priority**: LOW (unless required)

No archiving for compliance/legal hold.

**Use Case**: Some organizations need immutable mail archives.

**Solution**:
```nix
# BCC all mail to archive address
always_bcc = archive@example.com

# Or use Dovecot's mail-crypt plugin for encrypted archives
```

**Estimated Effort**: 8-16 hours (depending on requirements)

---

### 21. Webmail Interface

**Priority**: LOW

No webmail (e.g., Roundcube, SnappyMail) configured.

**Trade-off**: Additional attack surface vs. user convenience.

**Estimated Effort**: 4-8 hours

---

### 22. Sender Rewriting Scheme (SRS)

**Priority**: LOW

SRS for mail forwarding is commented out in `postfix.nix:232-238`.

**When Needed**: If forwarding mail and SPF is causing issues.

**Status**: Code exists but commented. Enable if needed.

---

## Testing & Quality

### 23. Automated Testing

**Priority**: MEDIUM

No automated tests for mail flow.

**Needed**:
- Integration tests for SMTP send/receive
- Authentication tests (SASL, LDAP)
- Spam filter tests (ensure training works)
- DKIM signature validation tests

**Estimated Effort**: 16-32 hours

---

### 24. Health Checks

**Priority**: MEDIUM

No automated health checks beyond systemd service status.

**Solution**:
```nix
# Add health check service
systemd.services.mail-health-check = {
  serviceConfig.Type = "oneshot";
  script = ''
    # Check SMTP
    nc -zv localhost 25 || exit 1
    nc -zv localhost 587 || exit 1

    # Check IMAP
    nc -zv localhost 143 || exit 1

    # Check auth
    echo "test" | doveadm auth test testuser || exit 1

    # Check Rspamd
    rspamc ping || exit 1

    # Check ClamAV
    clamdscan --version || exit 1
  '';
};

systemd.timers.mail-health-check = {
  wantedBy = [ "timers.target" ];
  timerConfig.OnCalendar = "hourly";
};
```

**Estimated Effort**: 4-8 hours

---

## Migrations

### 25. Dovecot 2.4 Migration

**Priority**: HIGH (deferred, not optional)

**Status**: Deferred. `dovecot.nix` pins `pkgs.dovecot_2_3` so it keeps running
on nixpkgs 26.05, which defaults to Dovecot 2.4.

**Background**: 26.05 ships Dovecot 2.4.5 and rewrote the NixOS module around a
freeform `services.dovecot2.settings`. The module migration is done (see the
26.05 fixes in dovecot.nix); what is NOT done is the move to 2.4 itself, which
is a genuine breaking change:

- **Config language**: `%u`/`%n` become `%{user}`/`%{user|username}`;
  `mail_location` splits into `mail_driver` + `mail_path`; `passdb`/`userdb`
  become named sections (`passdb ldap { ... }`); quota settings were rewritten.
- **old_stats is gone.** Everything under `service old-stats`, the
  `old_stats_*` plugin settings, the `old_stats` mail plugin and the
  `services.prometheus.exporters.dovecot` socket it feeds all depend on it.
  Metrics have to be rebuilt on 2.4's own stats/metrics support.
- **fts-flatcurve does not exist for 2.4** -- full-text search moved into
  Dovecot proper. nixpkgs builds `dovecot-fts-flatcurve` against `dovecot_2_3`
  only. The `fts`/`fts_flatcurve` mail plugins and the whole `plugin { fts... }`
  block need replacing with 2.4's built-in FTS.
- **Pigeonhole**: `pkgs.dovecot_pigeonhole` is the 2.4 build; the pin uses
  `dovecot_pigeonhole_0_5`. Sieve settings changed shape in 2.4 as well.

**Why it can't wait forever**: `dovecot_2_3` is the outgoing branch (2.3.21.1,
upstream has moved on) and will not stay in nixpkgs indefinitely. This should
be scheduled into a maintenance window with a test deployment, not done under
pressure when the package disappears.

**Approach**: migrate on a test host first, with a real mailbox and a real
client. Suggested order: config-language translation -> FTS -> metrics ->
Sieve, verifying IMAP login, LMTP delivery, spam/ham learning and search at
each step.

**Estimated Effort**: 1-3 days, plus a deployment window.

---

## Status Summary

Legend: **DONE** shipped and believed working / **PARTIAL** shipped but
incomplete or unverified / **OPEN** not started.

Ordered by what would most improve the deployment, not by item number.

### Do next

| # | Item | Status | Note |
| --- | --- | --- | --- |
| 23 | Automated testing | OPEN | Highest leverage in the list. A `nixosTest` booting the stack and exercising LMTP, IMAP login and both submission ports would have caught several shipped bugs on the first run. |
| 4 | Backup strategy | OPEN | `dkim` and `mail` under state-directory are unrecoverable if lost; `redis` is weeks of spam training. |
| 2 | Intrusion prevention | PARTIAL | fail2ban is configured, but its jails match host journal units while the services run in containers, and bans land in `INPUT` which container traffic bypasses. Probably matches nothing. Verify before relying on it. |
| 6 | Monitoring alerts | OPEN | Metrics are exposed; nothing alerts on them. |

### Shipped

| # | Item | Status | Note |
| --- | --- | --- | --- |
| 1 | Secrets management | PARTIAL | LDAP bind password and outpost token are read at runtime. The three `internal-secrets.*` still default to build-seed derivation in the Nix store; set the `*-file` options to close it. |
| 3 | DMARC support | DONE | Checking is on. Aggregate *reporting* is deliberately off — it needs a real org_name and a `rspamd_dmarc_report` timer. |
| 7 | Rate limiting | DONE | Now on the submission listeners only; applying them in main.cf throttled inbound mail from busy peers. |
| 9 | Recipient validation | DONE | LDAP recipient maps. |
| 10 | Mail quotas | DONE | Off by default; `quota.enable = true` to use. |
| 12 | TLSv1.1 deprecation | DONE | Expressed as `>=TLSv1.2`. |
| 14 | DNS documentation | DONE | See README. |
| 15 | Hyperscan | DONE | Build option, off on pre-SSE4.2 hosts. |
| 16 | Redis persistence | PARTIAL | The volume now points at `/var/lib/redis-rspamd`, where Redis actually writes — previously nothing persisted at all. Save/appendonly policy is still Redis' default. |

### Open

| # | Item | Status | Note |
| --- | --- | --- | --- |
| 5 | Log retention/aggregation | OPEN | Complicated by container logging; see README. |
| 8 | Greylisting | OPEN | Rspamd module exists, not enabled. |
| 11 | Certificate auto-renewal | OPEN | Certs are supplied to the module as directories; renewal is the host's job. |
| 13 | Hardcoded UID/GID 5025 | OPEN | Deliberate — documented in the README rather than changed. |
| 17 | Blacklist recommendations | OPEN | Documentation. |
| 18 | Sieve documentation | OPEN | Partly addressed: the scripts are now real files in `./sieves`. |
| 19 | Vacation/autoresponder | OPEN | |
| 20 | Compliance archive | OPEN | Only if needed. |
| 21 | Webmail | OPEN | Also the strongest reason to add OAuth. |
| 22 | SRS | OPEN | `useSrs` was removed upstream in favour of `services.pfix-srsd`. |
| 24 | Health checks | OPEN | |
| 25 | Dovecot 2.4 migration | OPEN | Deferred, not optional — `dovecot_2_3` will not stay in nixpkgs forever. Schedule it; do any OAuth work as part of it. |

### Not in this list

Findings from the repository review that have not been turned into numbered
items: eight host-verification items (does fail2ban match anything, is
per-user Sieve storage writable, is IPv6 reachable, is the metrics port
exposed, and so on). These need a running deployment to settle rather than a
code change.

---

## Notes

- Estimated efforts are rough and vary with the deployment.
- Some items (webmail, archiving) are not needed for every deployment.
- Test in staging before production.
- Revisit this file when items are completed — it drifted badly once already,
  with every item marked with a checkmark that meant "should be prioritized"
  while reading as "done".
