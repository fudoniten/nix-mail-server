# Mail Server Configuration

NixOS module configuration for a production mail server with comprehensive spam protection and modern security features.

## Architecture

This mail server runs as eight Arion containers in one project, `mail-server`.
Container names are also the service names used throughout this document.

```
                 Internet                       Mail clients
                    │                          │           │
              25 ───┤                    587/465           143/993
                    ▼                          ▼           ▼
            ┌───────────────┐            ┌───────────────┐
            │     smtp      │  LMTP :24  │     imap      │
            │    Postfix    │───────────▶│    Dovecot    │
            │  + Dovecot    │            │  + Pigeonhole │
            │   (SASL only) │            │  + Flatcurve  │
            └───────┬───────┘            └───┬───────┬───┘
         milters    │                        │       │
        ┌───────────┴──────┐        learn    │       │  auth
        ▼                  ▼        (Sieve)  │       │
┌───────────────┐  ┌──────────────┐          │       │
│   antispam    │  │     dkim     │◀─────────┘       │
│    Rspamd     │  │   OpenDKIM   │  :11335          │
└───┬───────┬───┘  └──────────────┘                  │
    │       │                                        │
    ▼       ▼                                        ▼
┌────────┐ ┌───────┐                        ┌────────────────┐
│antivirus│ │ redis │                       │   ldap-proxy   │
│ ClamAV │ │ Bayes │                        │Authentik outpost│
└────────┘ └───────┘                        └───────┬────────┘
                                                    ▼
                                                Authentik

  metrics-proxy (nginx, published on metrics-port) scrapes
  smtp:5035, imap:5036 and antispam:11336 on the internal network.
```

Four Docker/Podman networks separate the traffic: `external_network` (the only
one with outbound access — needed by smtp for delivery, antispam for RBL
lookups, antivirus for signature updates and ldap-proxy for Authentik),
`internal_network` for inter-service traffic, and `redis_network` and
`ldap_network` to keep those two backends off everything else.

### Component responsibilities

| Container | Runs | Role |
| --- | --- | --- |
| `smtp` | Postfix + a protocol-less Dovecot | SMTP on 25, submission on 587 and 465. The Dovecot here exists only to answer SASL over a socket. |
| `imap` | Dovecot + Pigeonhole + Flatcurve | IMAP on 143/993, LMTP delivery on 24, Sieve filtering, full-text search |
| `antispam` | Rspamd | Milter on 11335, controller on 11336. Bayes, neural net, reputation, RBL, and the ClamAV hand-off |
| `antivirus` | ClamAV | Signature scanning on 15407, with freshclam updates |
| `dkim` | OpenDKIM | Milter on 5734: signs outbound for local domains, verifies inbound |
| `redis` | Redis | Rspamd's statistics and learning backend |
| `ldap-proxy` | Authentik LDAP outpost | Turns LDAP on 3389 into Authentik auth |
| `metrics-proxy` | nginx | The only published metrics surface |

Both milters run on every message, in order: Rspamd first (so its headers get
signed), then OpenDKIM.

### Mail Flow

**Incoming mail:**
```
Internet → smtp:25 → client/RBL, sender, recipient and HELO restrictions
         → SPF policy check
         → milters: antispam (which calls antivirus) then dkim (verify)
         → LMTP to imap:24 → Sieve → Maildir
```

**Outgoing mail:**
```
Client → smtp:587 (STARTTLS) or smtp:465 (implicit TLS)
       → SASL auth against the in-container Dovecot, via ldap-proxy
       → sender login map check (no sending as anyone else)
       → milters: antispam (headers suppressed for authenticated senders)
                  then dkim (sign)
       → opportunistic TLS out to the destination MX
```

ClamAV is not a separate stage: Rspamd calls it as one of its checks, and
rejects on a hit.

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

### Host prerequisites

This module is not self-contained. The host configuration importing it must
also provide:

- **`virtualisation.arion.backend`** - `"docker"` or `"podman-socket"`. Arion
  declares this with no default, so leaving it unset fails evaluation with
  *"The option `virtualisation.arion.backend' is used but not defined"*.
- **`config.instance.build-seed`** - a fudo-lib provision, used to derive the
  internal passwords (Dovecot admin, Dovecot API key, Redis) when the
  corresponding `internal-secrets.*-file` option is left null.
- **`pkgs.lib.passwd.stablerandom-passwd-file`** - likewise from fudo-lib, and
  likewise only needed when those options are null.

Set all three `internal-secrets.*-file` options and `build-seed` is no longer
consulted, but the overlay providing `pkgs.lib.passwd` still has to be present.

### Required options

Every option below has no default and must be set:

```nix
fudo.mail = {
  enable = true;

  primary-domain = "example.com";
  state-directory = "/var/lib/mail";

  # SASL realm presented on the submission ports.
  sasl-domain = "example.com";

  # Directories holding fullchain.pem and key.pem for each hostname.
  smtp.ssl-directory = "/run/credentials/smtp-certs";
  imap.ssl-directory = "/run/credentials/imap-certs";

  ldap = {
    bind-dn = "cn=mail,ou=services,dc=example,dc=com";
    bind-password-file = "/run/secrets/mail-ldap-password";
    base = "dc=example,dc=com";

    # Exactly one of outpost-token / outpost-token-file. Setting both, or
    # neither, trips an assertion.
    outpost-token-file = "/run/secrets/authentik-outpost-token";
  };
};
```

Commonly set, but optional:

```nix
fudo.mail = {
  extra-domains = [ "example.org" ];

  # Default to smtp./imap. prefixed onto primary-domain.
  smtp.hostname = "smtp.example.com";
  imap.hostname = "imap.example.com";

  # Defaults to authentik.<primary-domain>.
  ldap.authentik-host = "authentik.example.com";

  # See TODO.md item 17 for blacklist recommendations.
  blacklist.dns = [ "zen.spamhaus.org" "bl.spamcop.net" ];

  quota.enable = true;
  fail2ban.enable = true;
};
```

Note `ldap.host` is **not** an option; the LDAP endpoint is the Authentik
outpost, addressed via `ldap.authentik-host`.

### One account namespace across all domains

Both Dovecot instances set `auth_username_format = %n`, and the Postfix sender
login map carries a catch-all per domain. The domain part of an address is
therefore discarded at authentication: `user@example.com` and
`user@example.org` are the **same account**, with the same mailbox and the same
password.

That is usually what you want for a personal or small-organisation server
hosting several domains. It is not what "multi-domain support" means elsewhere,
so it is worth knowing before adding a second domain whose users are meant to
be distinct people.

### Storage paths

All persistent state lives under `state-directory` on the host. With
`state-directory = "/var/lib/mail"`:

| Host path | Mounted in container at | Holds |
| --- | --- | --- |
| `/var/lib/mail/mail` | `imap:/mail` | User mailboxes (Maildir) |
| `/var/lib/mail/dovecot` | `imap:/state` | Dovecot indexes, Sieve scripts |
| `/var/lib/mail/dovecot-dhparams` | `imap:/var/lib/dhparams` | Generated DH parameters |
| `/var/lib/mail/dkim` | `dkim:/var/lib/opendkim` | DKIM private keys |
| `/var/lib/mail/antivirus` | `antivirus:/state` | ClamAV signature database |
| `/var/lib/mail/redis` | `redis:/var/lib/redis-rspamd` | Bayes, neural net, reputation |
| `/var/lib/mail/postfix` | `smtp:/var/lib/postfix` | Mail queue |

**Back up `dkim` and `mail`.** Losing DKIM keys means republishing DNS and a
period of failed signature verification; losing `mail` is unrecoverable. The
`redis` directory is worth backing up too — it is the accumulated spam training,
which takes weeks of real traffic to rebuild. `antivirus` and
`dovecot-dhparams` regenerate themselves and need no backup.

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

3. **Check the containers came up**:
   ```bash
   arion -p mail-server ps
   ```
   All of `smtp`, `imap`, `antispam`, `antivirus`, `dkim`, `redis`,
   `ldap-proxy` and `metrics-proxy` should be running.

4. **Generate DKIM keys** (auto-generated on the `dkim` container's first
   start). Verify them on the host, where they are persisted:
   ```bash
   ls -la /var/lib/mail/dkim/keys/
   ```

5. **Publish the DKIM public key to DNS** (see DNS Requirements)

6. **Test mail flow**:
   ```bash
   # Send a test message in
   swaks --to user@example.com --server <your-host>:25

   # Watch it move through the stack
   arion -p mail-server logs -f smtp antispam imap
   ```

7. **Test both submission ports**, since they fail independently:
   ```bash
   swaks --to user@example.com --from you@example.com \
         --server smtp.example.com:587 --auth LOGIN --auth-user you --tls
   swaks --to user@example.com --from you@example.com \
         --server smtp.example.com:465 --auth LOGIN --auth-user you --tlsc
   ```

8. **Verify DNS records**:
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

Metrics are **not** served on the host by each service. Every exporter listens
inside its own container, and a small nginx (`metrics-proxy`) is the only thing
published — on `metrics-port`, default 5034:

| Scrape URL | Proxied to |
| --- | --- |
| `http://<host>:5034/metrics/postfix` | `smtp:5035` |
| `http://<host>:5034/metrics/dovecot` | `imap:5036` |
| `http://<host>:5034/metrics/rspamd` | `antispam:11336` (rspamd's native OpenMetrics endpoint) |

No other path is proxied; anything else returns 404.

> **This port is exposed.** Published container ports are DNAT'd before the
> filter table, so `networking.firewall` does not gate them, and 5034 is not in
> the module's `allowedTCPPorts` either. The proxy has no authentication. If the
> host faces the internet, bind it to loopback or put auth in front of it.

### Common operations

All of these run *inside* a container. Prefix each with
`arion -p mail-server exec <service>`; the service is named in each heading.

#### Mail queue (`smtp`)
```bash
arion -p mail-server exec smtp mailq            # or: postqueue -p
arion -p mail-server exec smtp postqueue -f     # flush
arion -p mail-server exec smtp postsuper -d <queue-id>
arion -p mail-server exec smtp postsuper -d ALL deferred
```

The queue is persisted to `<state-directory>/postfix` on the host, so it now
survives container recreation.

#### Check spam scores
Look for `X-Spam`, `X-Spamd-Result` and `X-Rspamd-Server` headers in the source
of a received message. Note these are added on *inbound* mail only —
`skip_authenticated` keeps them off anything your own users send.

#### Train the spam filter manually (`antispam`)
```bash
arion -p mail-server exec antispam rspamc learn_spam < spam-message.eml
arion -p mail-server exec antispam rspamc learn_ham  < ham-message.eml
arion -p mail-server exec antispam rspamc stat
```

No `-h` needed from inside the container. Day to day this is automatic: moving
a message into Junk trains it as spam, moving one out trains it as ham, via the
Sieve scripts in `./sieves`.

#### Rspamd web UI (`antispam`)
The controller listens on port **11336** inside the container and is not
published to the host. Only `/metrics` is reachable, through the metrics proxy.
To reach the UI, forward the port yourself:

```bash
arion -p mail-server exec antispam rspamadm control stat   # or
ssh -L 11336:localhost:11336 <host>   # then browse via a port-forward
```

No controller password is configured, so treat the port as sensitive.

#### ClamAV status (`antivirus`)
```bash
arion -p mail-server exec antivirus systemctl status clamav-daemon
arion -p mail-server exec antivirus systemctl status clamav-freshclam
arion -p mail-server exec antivirus clamdscan --version
```

#### Regenerate DKIM keys (`dkim`)
Keys live at `<state-directory>/dkim/keys` on the host, which is
`/var/lib/opendkim/keys` inside the container. Either path reaches the same
files, so the backup step is easiest done host-side:

```bash
arion -p mail-server stop dkim
mv /var/lib/mail/dkim/keys /var/lib/mail/dkim/keys.backup
arion -p mail-server start dkim

# Read the new public key and publish it at mail._domainkey.example.com
cat /var/lib/mail/dkim/keys/example.com/mail.txt
```

Publish the new TXT record **before** the old key stops being used, or outbound
mail fails DKIM verification in the gap.

### Log locations

Every service runs inside a container, so `journalctl -u postfix` on the host
finds nothing — there is no such unit. Reach the containers through Arion
instead. The project is named `mail-server`, and the services are `smtp`,
`imap`, `antispam`, `antivirus`, `dkim`, `redis`, `ldap-proxy` and
`metrics-proxy`.

```bash
# Whole project, following
arion -p mail-server logs -f

# One service
arion -p mail-server logs -f smtp
arion -p mail-server logs -f antispam

# A shell inside a container, where the usual unit names DO work
arion -p mail-server exec smtp journalctl -u postfix -n 100
arion -p mail-server exec imap journalctl -u dovecot -n 100
arion -p mail-server exec antispam journalctl -u rspamd -n 100
```

Note the Dovecot unit is `dovecot.service`. nixpkgs used to alias
`dovecot2.service` to it; 26.05 dropped the alias.

The host units that *do* exist are the ones this module adds directly:

```bash
journalctl -u arion-mail-server   # container orchestration
journalctl -u mail-secrets        # boot-time secret assembly
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

### Current security model

- **TLS**: required for submission (587 STARTTLS, 465 implicit) and IMAPS (993);
  opportunistic on port 25 in both directions, which is all a public MX can do.
  TLS 1.2+ only.
- **Authentication**: LDAP via the Authentik outpost. Plaintext auth is refused
  on the IMAP instance; the SASL instance serves no protocols at all.
- **Sender validation**: `reject_sender_login_mismatch` stops an authenticated
  user sending as anyone else, and stops unauthenticated senders forging a
  local domain.
- **Multi-layer filtering**: restrictions at the client, sender, relay,
  recipient and HELO stages, with DNS blacklists consulted once at the client
  stage.
- **Rate limiting**: per-client-IP message, recipient and connection limits on
  the submission listeners, to contain a compromised account. Port 25 is
  deliberately unlimited so busy legitimate peers are not deferred.
- **Spam protection**: Rspamd (Bayes, neural net, reputation, RBL) + ClamAV.
- **Email signing**: DKIM on all outbound mail.

### Known security issues

**See TODO.md for the detailed list.** The ones worth knowing before deploying:

1. **The metrics proxy is unauthenticated and firewall-exempt.** Published
   container ports bypass `networking.firewall`, so `metrics-port` (5034) is
   reachable from anywhere the host is. See the Monitoring section.

2. **fail2ban probably does not work here**, even when `fail2ban.enable` is set.
   The jails match on `_SYSTEMD_UNIT=postfix.service`, but Postfix and Dovecot
   run in containers and their logs reach the journal tagged with the container
   runtime's unit instead; and bans land in `INPUT`, which DNAT'd container
   traffic bypasses. `fail2ban-client status postfix-sasl` showing zero matches
   over a period when the logs show failed logins confirms it.

3. **Internal secrets default to build-seed derivation.** The Dovecot admin
   password, Dovecot API key and Redis password are, by default, derived
   deterministically from `build-seed` and land in the world-readable Nix store.
   The LDAP bind password and Authentik outpost token are read at runtime and
   never do. Point the three `internal-secrets.*-file` options at a real secrets
   store to close this.

4. **The Rspamd controller has no password.** It is not published to the host,
   so this only matters to anything else on the container networks.

## Troubleshooting

### Mail not being delivered

1. **Check the queue**: `arion -p mail-server exec smtp mailq`
2. **Check the logs**: `arion -p mail-server logs --tail 100 smtp`
3. **Common causes**:
   - Reverse DNS not configured, or not matching `smtp.hostname`
   - SPF/DKIM/DMARC records incorrect or missing
   - IP address blacklisted (check mxtoolbox.com)
   - Recipient server blocking (read the bounce)

### Authentication failures

1. **Check LDAP connectivity** from inside the container that does the lookup —
   the Authentik outpost is on an internal network and is not reachable from the
   host:
   ```bash
   arion -p mail-server exec imap \
     ldapsearch -H ldap://ldap-proxy:3389 -D "<bind-dn>" -W -b "<base>"
   ```
2. **Check Dovecot auth logs**:
   `arion -p mail-server exec imap journalctl -u dovecot | grep auth`
3. **Check the outpost itself**: `arion -p mail-server logs ldap-proxy`
4. **Enable debug mode**: set `fudo.mail.debug = true`, which turns on
   `auth_debug` in both Dovecot instances and verbose Postfix logging.

Remember the domain part of the login is discarded (see *One account namespace*
above) — authenticating as `user@example.com` and `user` are the same thing.

### Spam not being caught

1. **Is Rspamd running**:
   `arion -p mail-server exec antispam systemctl status rspamd`
2. **Is Bayes actually trained**:
   `arion -p mail-server exec antispam rspamc stat`
   — a corpus of zero means learning is not reaching Redis.
3. **Is Redis persisting**: `ls <state-directory>/redis`. If that directory is
   empty on a server that has been running a while, training is being thrown
   away on every rebuild.
4. **Is ClamAV running**:
   `arion -p mail-server exec antivirus systemctl status clamav-daemon`
5. **Review the headers**: `X-Spamd-Result` on a received message shows every
   symbol that fired and its score.
6. **Train it**: moving mail into and out of Junk trains it automatically.

### High CPU Usage

**Vectorscan/Hyperscan**: rspamd is built with hyperscan by default. Vectorscan needs SSE4.2 + POPCNT, so on a pre-Nehalem CPU (e.g. a Xeon L5420, which only reaches SSSE3) rspamd dies with "Illegal instruction" -- set `fudo.mail.antispam.hyperscan = false;` there and rspamd falls back to PCRE-based regex matching, which is slower. Drop that setting again after moving to hardware with SSE4.2+.

### Mail Storage Full

1. **Check disk space**: `df -h /var/lib/mail`
2. **Find large mailboxes**:
   ```bash
   du -sh /var/lib/mail/mail/* | sort -h
   ```
3. **Consider**:
   - Turning on quotas: `fudo.mail.quota.enable = true` with `quota.limit`
   - Auto-expunge, already configured for Trash (30d), Junk and Drafts (60d)
   - `quota.exemptions` for accounts that should not be capped

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

- **Legacy CPU support**: vectorscan needs SSE4.2+; on older CPUs (Xeon L5420 has SSSE3 only) set `fudo.mail.antispam.hyperscan = false`
- **UID/GID**: Fixed at 5025 for mail user/group

### Recommended Specs

- **CPU**: Any x64 processor (SSE4.2+ recommended, so vectorscan can be left enabled for faster spam filtering)
- **RAM**: 2GB minimum, 4GB+ recommended
- **Disk**: SSD strongly recommended for mail storage and indexes
- **Network**: Static IP with reverse DNS

## Support & Resources

### Documentation

- See inline comments in each `.nix` file for detailed explanations
- See `TODO.md` for planned improvements and known issues

### Useful commands

All container-side, via `arion -p mail-server exec <service>`:

```bash
# Postfix config check and effective settings
arion -p mail-server exec smtp postfix check
arion -p mail-server exec smtp postconf -n

# Dovecot effective config (both instances -- smtp runs a SASL-only one)
arion -p mail-server exec imap doveconf -n
arion -p mail-server exec smtp doveconf -n

# Rspamd config check
arion -p mail-server exec antispam rspamadm configtest

# Per-container service status
arion -p mail-server exec smtp      systemctl status postfix
arion -p mail-server exec imap      systemctl status dovecot
arion -p mail-server exec antispam  systemctl status rspamd
arion -p mail-server exec antivirus systemctl status clamav-daemon
arion -p mail-server exec dkim      systemctl status opendkim

# Whole stack, from the host
arion -p mail-server ps
```

### External Testing Tools

- **MXToolbox**: https://mxtoolbox.com/ (DNS, blacklists, SMTP test)
- **Mail Tester**: https://www.mail-tester.com/ (comprehensive scoring)
- **DKIM Validator**: https://dkimvalidator.com/
- **SPF Check**: https://www.kitterman.com/spf/validate.html

## Version Information

- **nixpkgs**: `nixos-26.05`. The modules use the 26.05 rewrites of
  `services.dovecot2` and `services.postfix` (`settings.main`,
  `settings.master`, `includeFiles`) and do not evaluate on 25.11.
- **Arion**: unpinned (`github:hercules-ci/arion`), following this flake's
  nixpkgs.
- **Postfix**: System default (via NixOS)
- **Dovecot**: pinned to 2.3 (`pkgs.dovecot_2_3`), NOT the system default --
  nixpkgs 26.05 defaults to 2.4, which is a breaking change for this
  configuration. See TODO.md item 25 for the migration; the pin also forces
  `dovecot_pigeonhole_0_5` and is why `dovecot-fts-flatcurve` still works.
- **Rspamd**: System default (via NixOS)
- **ClamAV**: System default (via NixOS)
- **OpenDKIM**: System default (via NixOS)

Check versions with:
```bash
arion -p mail-server exec smtp      postconf mail_version
arion -p mail-server exec imap      doveconf -n | grep "^# "
arion -p mail-server exec antispam  rspamd --version
arion -p mail-server exec antivirus clamd --version
arion -p mail-server exec dkim      opendkim -V
```
