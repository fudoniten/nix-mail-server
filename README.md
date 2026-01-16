# Mail Server Configuration

NixOS module configuration for a production mail server with comprehensive spam protection and modern security features.

## Architecture

This mail server uses a container-based architecture with the following components:

```
┌─────────────────────────────────────────────────────────────┐
│                      Internet Traffic                        │
└────────────────┬────────────────────────┬────────────────────┘
                 │                        │
         ┌───────▼────────┐      ┌───────▼────────┐
         │  Postfix SMTP  │      │ Dovecot IMAP   │
         │  (25/587/465)  │      │   (143/993)    │
         └───────┬────────┘      └───────┬────────┘
                 │                       │
         ┌───────▼────────┐      ┌──────▼─────────┐
         │    Rspamd      │◄─────┤  Sieve Scripts │
         │ Spam Filtering │      │  (ham/spam.sh) │
         └───────┬────────┘      └────────────────┘
                 │
         ┌───────▼────────┐
         │     ClamAV     │
         │ Virus Scanning │
         └────────────────┘
                 │
         ┌───────▼────────┐
         │   OpenDKIM     │
         │  Email Signing │
         └────────────────┘
                 │
         ┌───────▼────────┐      ┌────────────────┐
         │     Redis      │      │  LDAP/Authentik│
         │ Bayes/Stats DB │      │ Authentication │
         └────────────────┘      └────────────────┘
```

### Component Responsibilities

- **Postfix**: SMTP server for sending/receiving mail
- **Dovecot**: IMAP server for mail access + LMTP for local delivery
- **Rspamd**: Multi-layer spam filtering (Bayes, neural nets, reputation, RBL)
- **ClamAV**: Antivirus scanning with automatic database updates
- **OpenDKIM**: DKIM signing for outbound, verification for inbound
- **Redis**: Backend for spam learning and statistics
- **Authentik**: LDAP authentication provider

### Mail Flow

**Incoming Mail:**
```
Internet → Postfix:25 → SPF Check → Rspamd → ClamAV → DKIM Verify →
Dovecot LMTP → Sieve Filters → Maildir Storage
```

**Outgoing Mail:**
```
Client → Postfix:587 → SASL Auth → Sender Check → Rspamd → ClamAV →
DKIM Sign → Internet
```

**Spam Learning:**
```
User moves to/from Junk → Sieve Script → rspamc learn_spam/ham →
Redis Bayes Update
```

## DNS Requirements

### Critical DNS Records

You **must** configure these DNS records for the mail server to function properly:

#### MX Records
```
example.com.        IN  MX  10 mail.example.com.
```

#### A/AAAA Records
```
mail.example.com.   IN  A     <your-ipv4>
mail.example.com.   IN  AAAA  <your-ipv6>
```

#### PTR (Reverse DNS)
```
<reverse-ip>.in-addr.arpa.  IN  PTR  mail.example.com.
```
**Critical**: Many mail servers reject mail if reverse DNS doesn't match. Contact your hosting provider to set this up.

#### SPF Record
```
example.com.  IN  TXT  "v=spf1 mx -all"
```
Or more specific:
```
example.com.  IN  TXT  "v=spf1 ip4:<your-ipv4> ip6:<your-ipv6> -all"
```

#### DKIM Record
After generating DKIM keys (see Maintenance section), publish the public key:
```
mail._domainkey.example.com.  IN  TXT  "v=DKIM1; k=rsa; p=<public-key-base64>"
```

To get your public key:
```bash
cat /var/lib/opendkim/keys/example.com/mail.txt
```

#### DMARC Record
```
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com; ruf=mailto:postmaster@example.com; fo=1"
```

Policies:
- `p=none` - Monitor only (start here)
- `p=quarantine` - Suspect mail goes to spam
- `p=reject` - Reject failed mail (strictest)

## Configuration

### Required Options

```nix
fudo.mail = {
  enable = true;
  primary-domain = "example.com";
  extra-domains = [ "example.org" ];

  state-directory = "/var/lib/mail";

  smtp.hostname = "smtp.example.com";
  imap.hostname = "imap.example.com";

  ldap = {
    host = "ldap.example.com";
    bind-dn = "cn=mail,ou=services,dc=example,dc=com";
    bind-password-file = "/secrets/ldap-password";
  };

  # See TODO.md for blacklist recommendations
  blacklist.dns = [
    "zen.spamhaus.org"
    "bl.spamcop.net"
  ];
};
```

### Storage Paths

**Important**: These paths need adequate disk space and should be backed up:

- `/var/lib/mail/mail` - User mailboxes (Maildir format)
- `/var/lib/mail/dovecot` - Dovecot state, indexes, Sieve scripts
- `/var/lib/opendkim` - DKIM private keys (**critical to backup**)
- `/var/lib/clamav` - Virus definition database
- `/var/lib/redis` - Spam learning data (Bayes, neural net)

### User/Group IDs

**Critical**: This configuration uses hardcoded UID/GID 5025 for mail storage. This ensures consistent file ownership across deployments and when restoring from backups.

If you're migrating from another system, you'll need to chown the mail directory:
```bash
chown -R 5025:5025 /var/lib/mail/mail
```

## Deployment

### Initial Setup

1. **Configure DNS records** (see DNS Requirements above)

2. **Deploy the NixOS configuration**:
   ```bash
   nixos-rebuild switch
   ```

3. **Generate DKIM keys** (if not already present):
   ```bash
   # Keys are auto-generated on first start
   # Verify they exist:
   ls -la /var/lib/opendkim/keys/
   ```

4. **Publish DKIM public key to DNS** (see DNS Requirements)

5. **Test mail flow**:
   ```bash
   # Send test email
   echo "Test" | mail -s "Test" user@example.com

   # Check logs
   journalctl -u postfix -f
   journalctl -u dovecot2 -f
   ```

6. **Verify DNS records**:
   ```bash
   # Check MX
   dig MX example.com

   # Check SPF
   dig TXT example.com

   # Check DKIM
   dig TXT mail._domainkey.example.com

   # Check DMARC
   dig TXT _dmarc.example.com

   # Check reverse DNS
   dig -x <your-ip>
   ```

## Maintenance

### Monitoring

All services expose Prometheus metrics:

- Postfix metrics: `:1725/metrics`
- Dovecot metrics: `:5034/metrics`
- Rspamd metrics: `:7573/metrics`

### Common Operations

#### View Mail Queue
```bash
mailq
# or
postqueue -p
```

#### Flush Mail Queue
```bash
postqueue -f
```

#### Delete Message from Queue
```bash
postsuper -d <queue-id>
```

#### Delete All Deferred Mail
```bash
postsuper -d ALL deferred
```

#### Check Spam Scores
Look for `X-Spam-Score` and `X-Spam-Report` headers in email source.

#### Train Spam Filter Manually
```bash
# Learn as spam
rspamc -h rspamd learn_spam < spam-message.eml

# Learn as ham
rspamc -h rspamd learn_ham < ham-message.eml

# Check Bayes statistics
rspamc -h rspamd stat
```

#### View Rspamd Web UI
Access the controller at `http://mail-server:11334` (configure password first).

#### Check ClamAV Status
```bash
systemctl status clamav-daemon
systemctl status clamav-updater

# Check database version
clamdscan --version
```

#### Regenerate DKIM Keys
```bash
# Stop OpenDKIM
systemctl stop opendkim

# Backup old keys
mv /var/lib/opendkim/keys /var/lib/opendkim/keys.backup

# Restart to generate new keys
systemctl start opendkim

# Update DNS with new public key
cat /var/lib/opendkim/keys/example.com/mail.txt
```

### Log Locations

```bash
# Postfix
journalctl -u postfix

# Dovecot
journalctl -u dovecot2

# Rspamd
journalctl -u rspamd

# ClamAV
journalctl -u clamav-daemon
journalctl -u clamav-updater

# OpenDKIM
journalctl -u opendkim
```

### Testing Email Delivery

#### Test SMTP Authentication
```bash
# Test login
swaks --to user@example.com \
      --from sender@example.com \
      --server smtp.example.com:587 \
      --auth LOGIN \
      --auth-user sender \
      --tls
```

#### Test Spam Scoring
Send yourself a test with spam trigger words, or use:
```bash
# GTUBE spam test
swaks --to user@example.com \
      --from test@example.com \
      --server smtp.example.com:25 \
      --body "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
```

#### Check Mail Server Reputation
- https://mxtoolbox.com/SuperTool.aspx
- https://www.mail-tester.com/
- https://www.dnswl.org/ (check if you're whitelisted)

## Security Notes

### Current Security Model

- **TLS**: Required for submission (587/465) and IMAP (993), optional for SMTP (25)
- **Authentication**: LDAP via Authentik
- **Sender Validation**: `reject_sender_login_mismatch` prevents spoofing
- **Multi-layer Filtering**: Restrictions at sender, relay, recipient, client, HELO levels
- **Spam Protection**: Rspamd (Bayes, neural nets, RBL) + ClamAV
- **Email Signing**: DKIM for all outbound mail

### Known Security Issues

**See TODO.md for detailed list**, but critically:

1. **Secrets in Nix Store**: Passwords are currently stored in world-readable Nix store. This needs to be migrated to runtime secret injection (systemd `LoadCredential` or similar).

2. **No Intrusion Prevention**: No fail2ban or similar configured. Brute force attacks are not automatically blocked.

3. **No Rate Limiting**: No outbound rate limits configured. If an account is compromised, it could be used to send spam.

## Troubleshooting

### Mail Not Being Delivered

1. **Check queue**: `mailq`
2. **Check logs**: `journalctl -u postfix -n 100`
3. **Common issues**:
   - Reverse DNS not configured
   - SPF/DKIM records incorrect or missing
   - IP address blacklisted (check mxtoolbox.com)
   - Recipient server blocking (check bounce messages)

### Authentication Failures

1. **Check LDAP connectivity**:
   ```bash
   ldapsearch -H ldap://authentik -D "bind-dn" -W -b "base-dn"
   ```
2. **Check Dovecot auth logs**: `journalctl -u dovecot2 | grep auth`
3. **Enable debug mode** in configuration (see `debug` options)

### Spam Not Being Caught

1. **Check if Rspamd is running**: `systemctl status rspamd`
2. **Verify Bayes training**: `rspamc stat`
3. **Check if ClamAV is running**: `systemctl status clamav-daemon`
4. **Review spam headers**: Look for `X-Spam-Score` in message headers
5. **Train filter**: Users should move spam to Junk folder (auto-learning)

### High CPU Usage

**Likely hyperscan disabled**: This is expected. Hyperscan is disabled because the current mail servers run on older hardware without SSE4.2 CPU instructions. Performance impact is acceptable for our mail volume. Can re-enable after hardware upgrade.

### Mail Storage Full

1. **Check disk space**: `df -h /var/lib/mail`
2. **Find large mailboxes**:
   ```bash
   du -sh /var/lib/mail/mail/* | sort -h
   ```
3. **Consider**:
   - Implementing quotas (see TODO.md)
   - Auto-expunge of Trash/Junk (partially implemented)
   - User notification

## Performance Tuning

### Current Settings

- Rspamd workers: 4 (adjust based on mail volume)
- Dovecot max connections per user: 5
- Postfix message size limit: Configurable (default 100-200MB)

### For High Volume

Consider increasing:
- Rspamd worker count
- Dovecot connection limits
- Postfix process limits (in `master.cf` overrides)

## Hardware Requirements

### Current Limitations

- **Old hardware**: Hyperscan disabled due to lack of SSE4.2 instructions
- **UID/GID**: Fixed at 5025 for mail user/group

### Recommended Specs

- **CPU**: Modern x64 with SSE4.2 (for hyperscan when re-enabled)
- **RAM**: 2GB minimum, 4GB+ recommended
- **Disk**: SSD strongly recommended for mail storage and indexes
- **Network**: Static IP with reverse DNS

## Support & Resources

### Documentation

- See inline comments in each `.nix` file for detailed explanations
- See `TODO.md` for planned improvements and known issues

### Useful Commands

```bash
# Postfix configuration check
postfix check

# Test Postfix config
postconf -n

# Dovecot configuration check
doveconf -n

# Rspamd configuration check
rspamadm configtest

# Mail system status
systemctl status postfix dovecot2 rspamd clamav-daemon opendkim
```

### External Testing Tools

- **MXToolbox**: https://mxtoolbox.com/ (DNS, blacklists, SMTP test)
- **Mail Tester**: https://www.mail-tester.com/ (comprehensive scoring)
- **DKIM Validator**: https://dkimvalidator.com/
- **SPF Check**: https://www.kitterman.com/spf/validate.html

## Version Information

- **Postfix**: System default (via NixOS)
- **Dovecot**: System default (via NixOS)
- **Rspamd**: System default (via NixOS)
- **ClamAV**: System default (via NixOS)
- **OpenDKIM**: System default (via NixOS)

Check versions with:
```bash
postconf mail_version
doveconf -n | grep "^# "
rspamd --version
clamd --version
opendkim -V
```
