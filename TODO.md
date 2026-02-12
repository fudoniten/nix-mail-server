# TODO & Improvements

## Recently Fixed Issues ✅

### Critical Bug: Group Aliases Malformed [FIXED]

**Status: FIXED** - The `mkAliasUsers` function in `postfix.nix` was generating invalid virtual alias entries.

**Bug**: Line 397 used bare usernames instead of full email addresses for group alias recipients.

**Impact**: Group aliases (e.g., `support@domain` → multiple users) would fail to deliver because Postfix expected full email addresses for virtual mailbox delivery.

**Fix**: Changed `concatStringsSep "," users` to `userList users` to properly format recipient addresses.

---

## Critical Security Issues

### 1. Secrets in Nix Store [CRITICAL]

**Priority: HIGH**

Currently, secrets are embedded directly in the Nix store which is world-readable:

- `rspamd.nix:91`: Redis password embedded in config
- `mail-server.nix:224,456`: LDAP bind password via `readFile`
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

### 2. No Intrusion Prevention System [COMPLETED ✅]

**Priority: HIGH**

**Status: COMPLETED** - fail2ban is now configured with jails for Postfix SASL and Dovecot authentication.

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

No backup configuration or documentation for critical data:
- User mailboxes (`/var/lib/mail/mail`)
- DKIM private keys (`/var/lib/opendkim`)
- Rspamd learning data (`/var/lib/redis`)
- Dovecot indexes and state

**Impact**: Data loss in case of hardware failure or corruption.

**Solution Options**:

1. **Add backup module**:
```nix
services.restic.backups.mail = {
  repository = "s3:bucket/mail-backups";
  paths = [
    "/var/lib/mail"
    "/var/lib/opendkim"
    "/var/lib/redis"
  ];
  timerConfig = {
    OnCalendar = "daily";
  };
  exclude = [
    "/var/lib/mail/*/Trash"
    "/var/lib/mail/*/Junk"
  ];
};
```

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

**Status**: Hyperscan is now enabled via a custom vectorscan build.

**Background**: The standard vectorscan package in nixpkgs builds with AVX2/AVX512
support, which can cause crashes on older CPUs that only support SSSE3. Rather than
disabling hyperscan entirely (which rspamd 3.x doesn't cleanly support), we now
build vectorscan with the fat runtime but only SSSE3 baseline support.

**Solution Applied**:
The flake.nix now includes an overlay that builds vectorscan with:
- `FAT_RUNTIME=ON` - Runtime CPU detection for optimal performance
- `BUILD_AVX2=OFF` - Disabled to support older CPUs
- `BUILD_AVX512=OFF` - Disabled to support older CPUs

This allows rspamd to use hyperscan's fast regex matching even on older hardware.
The fat runtime will automatically use the best available implementation for the
host CPU at runtime.

**Future Optimization**: After upgrading to modern hardware with AVX2/AVX512 support,
remove the `legacyCpuOverlay` from flake.nix to use the standard nixpkgs vectorscan
build and gain additional performance.

---

### 16. Redis Persistence Configuration

**Priority**: LOW

Redis persistence not explicitly configured. Using defaults.

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

## Priority Summary

### Immediate (Next Sprint)
1. ✅ **Secrets Management** - Critical security issue
2. ✅ **Intrusion Prevention (fail2ban)** - Critical security issue
3. ✅ **Backup Strategy** - Critical operational issue

### Short Term (Next Month)
4. ✅ **DMARC Support** - Important security feature
5. ✅ **Rate Limiting** - Prevent abuse
6. ✅ **Monitoring Alerts** - Operational visibility
7. ✅ **Recipient Validation** - Reduce backscatter

### Medium Term (Next Quarter)
8. ✅ **Log Aggregation** - Better debugging
9. ✅ **Certificate Auto-renewal** - Operational improvement
10. ✅ **Mail Quotas** - Prevent disk space issues
11. ✅ **Greylisting** - Additional spam protection

### Long Term (When Needed)
12. ✅ **Hyperscan** - Enabled via SSSE3-only vectorscan build (see item 15)
13. ✅ **Vacation/Autoresponder** - User feature
14. ✅ **Archive** - If compliance needed
15. ✅ **Webmail** - User convenience
16. ✅ **Automated Testing** - Quality assurance

---

## Notes

- Items marked ✅ indicate they should be prioritized based on security/operational impact
- Estimated efforts are rough and may vary based on specific requirements
- Some features (like webmail, archiving) may not be needed for all deployments
- Test all changes in staging environment before production deployment
- Review and update this TODO periodically as items are completed or priorities change
