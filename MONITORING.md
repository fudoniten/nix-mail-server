# Mail Server Monitoring

Automated monitoring for your mail server with comprehensive testing and ntfy.sh notifications.

## Features

- **IMAP Authentication Test** - Validates IMAP login on port 993
- **SMTP Authentication Test** - Validates SMTP login on port 587
- **Send Test** - Sends a test email with unique tracking ID
- **Receive Test** - Confirms email delivery within timeout period
- **Smart Alerting** - Only notifies on state changes (failure → recovery)
- **Automatic Cleanup** - Removes old test emails from inbox
- **Security Hardened** - Runs with minimal privileges via systemd

## Quick Start

### Option 1: As a NixOS Module (Recommended)

Add the flake to your system configuration:

```nix
{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.05";
    mail-server.url = "github:fudoniten/nix-mail-server";
  };

  outputs = { self, nixpkgs, mail-server, ... }: {
    nixosConfigurations.your-host = nixpkgs.lib.nixosSystem {
      modules = [
        mail-server.nixosModules.mail-monitor
        {
          services.mail-monitor = {
            enable = true;
            interval = "15min";  # Check every 15 minutes

            smtp.host = "mail.example.com";
            imap.host = "mail.example.com";

            credentials = {
              username = "monitor@example.com";
              passwordFile = "/run/secrets/mail-monitor-password";
            };

            ntfy = {
              enable = true;
              topic = "my-mail-alerts";
              server = "https://ntfy.sh";  # or your self-hosted instance
            };
          };
        }
      ];
    };
  };
}
```

Create the password file:
```bash
# Using sops-nix, agenix, or manually:
echo -n "your-password" > /run/secrets/mail-monitor-password
chmod 600 /run/secrets/mail-monitor-password
```

Rebuild your system:
```bash
sudo nixos-rebuild switch
```

### Option 2: As a Standalone Package

Run the monitor directly:

```bash
# Run once
nix run github:fudoniten/nix-mail-server#mail-monitor -- \
  --smtp-host mail.example.com \
  --imap-host mail.example.com \
  --username monitor@example.com \
  --password "your-password" \
  --ntfy-topic my-mail-alerts

# Or install it
nix profile install github:fudoniten/nix-mail-server#mail-monitor
mail-monitor --config config.json
```

## Configuration

### Module Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable` | bool | `false` | Enable mail monitoring |
| `interval` | string | `"15min"` | Check interval (systemd format) |
| `smtp.host` | string | - | SMTP server hostname |
| `smtp.port` | int | `587` | SMTP port |
| `imap.host` | string | - | IMAP server hostname |
| `imap.port` | int | `993` | IMAP port |
| `credentials.username` | string | - | Email username |
| `credentials.passwordFile` | path | - | Path to password file |
| `testRecipient` | string? | `null` | Test recipient (defaults to username) |
| `receiveTimeout` | int | `60` | Receive timeout in seconds |
| `ntfy.enable` | bool | `true` | Enable ntfy.sh notifications |
| `ntfy.topic` | string | - | Ntfy.sh topic name |
| `ntfy.server` | string | `"https://ntfy.sh"` | Ntfy.sh server URL |
| `stateDirectory` | string | `"/var/lib/mail-monitor"` | State storage path |

### Config File Format (JSON)

```json
{
  "smtp_host": "mail.example.com",
  "smtp_port": 587,
  "imap_host": "mail.example.com",
  "imap_port": 993,
  "username": "monitor@example.com",
  "password": "your-password",
  "test_recipient": "monitor@example.com",
  "receive_timeout": 60,
  "ntfy_topic": "my-mail-alerts",
  "ntfy_server": "https://ntfy.sh",
  "state_file": "/var/lib/mail-monitor/state.json"
}
```

## Ntfy.sh Setup

### Using Public ntfy.sh

1. Choose a unique topic name: `my-mail-server-$(uuidgen | cut -d- -f1)`
2. Subscribe on your phone: [Install ntfy app](https://ntfy.sh/docs/subscribe/phone/)
3. Configure the topic in your mail-monitor settings

### Self-Hosted ntfy.sh

```nix
services.mail-monitor.ntfy.server = "https://ntfy.your-domain.com";
```

### Notification Examples

**Failure Alert:**
```
🚨 Mail Server Alert
Priority: High

Mail server monitoring detected failures:

• SMTP auth failed: [Errno 111] Connection refused
• Send Test: SMTP auth failed
```

**Recovery Alert:**
```
✅ Mail Server Recovered
Priority: Default

Mail server monitoring: all tests passing
```

## Monitoring Setup Best Practices

### 1. Create a Dedicated Monitoring Account

```bash
# On your mail server or LDAP/Authentik
# Create user: monitor@yourdomain.com
# Grant only IMAP/SMTP access (no admin)
```

### 2. Use Secret Management

**With sops-nix:**
```nix
sops.secrets.mail-monitor-password = {
  sopsFile = ./secrets.yaml;
  owner = "mail-monitor";
};

services.mail-monitor.credentials.passwordFile =
  config.sops.secrets.mail-monitor-password.path;
```

**With agenix:**
```nix
age.secrets.mail-monitor-password.file = ./secrets/mail-password.age;

services.mail-monitor.credentials.passwordFile =
  config.age.secrets.mail-monitor-password.path;
```

### 3. Adjust Check Interval

- **Production servers**: `"15min"` (default)
- **Critical servers**: `"5min"`
- **Development**: `"1h"`

### 4. Monitor Delivery Time

Check logs for delivery speed:
```bash
journalctl -u mail-monitor.service | grep "delivered in"
# Example: ✓ Receive Test: Email delivered in 2.3s
```

If consistently slow (>30s), investigate mail server performance.

## Testing

### Manual Test Run

```bash
# As root or mail-monitor user
sudo systemctl start mail-monitor.service

# Check status
systemctl status mail-monitor.service

# View logs
journalctl -u mail-monitor.service -n 50
```

### Expected Output

```
✓ IMAP Auth: OK
✓ SMTP Auth: OK
✓ Send Test: OK (Message-ID: <abc123@mail.example.com>)
✓ Receive Test: Email delivered in 2.1s
```

### Test Notification Sending

```bash
# Send test ntfy notification
curl -d "Test notification from mail-monitor" \
  https://ntfy.sh/your-topic-name
```

## Troubleshooting

### Service Won't Start

```bash
# Check configuration
nix eval .#nixosConfigurations.your-host.config.services.mail-monitor

# Verify password file exists and is readable
sudo -u mail-monitor cat /run/secrets/mail-monitor-password

# Check systemd status
systemctl status mail-monitor.service
```

### Authentication Failures

```bash
# Test IMAP manually
openssl s_client -connect mail.example.com:993
# Then: a1 LOGIN username password

# Test SMTP manually
openssl s_client -starttls smtp -connect mail.example.com:587
# Then: EHLO test
# Then: AUTH PLAIN <base64 encoded credentials>
```

### Email Not Received

1. Check receive timeout: `services.mail-monitor.receiveTimeout = 120;`
2. Verify email isn't caught in spam filters
3. Check mail server logs for delivery issues
4. Ensure test recipient mailbox isn't full

### Notifications Not Received

```bash
# Check if ntfy.sh is reachable
curl -d "test" https://ntfy.sh/your-topic

# View service logs for ntfy errors
journalctl -u mail-monitor.service | grep ntfy
```

### State File Issues

```bash
# Reset state (will trigger new notifications)
sudo rm /var/lib/mail-monitor/state.json
sudo systemctl start mail-monitor.service
```

## Architecture

### Test Flow

1. **IMAP Auth Test** → Connect to IMAP:993, login, disconnect
2. **SMTP Auth Test** → Connect to SMTP:587, STARTTLS, login, disconnect
3. **Send Test** → Authenticate, send email with unique Message-ID
4. **Receive Test** → Poll IMAP every 2s for up to 60s
5. **Cleanup** → Delete test email + old monitoring emails
6. **State Check** → Compare to previous state
7. **Notify** → Send ntfy.sh alert if state changed

### State Management

State file tracks:
```json
{
  "last_status": "healthy",
  "last_failure": {
    "timestamp": "2026-01-16T10:30:00",
    "failures": ["SMTP auth failed: Connection refused"]
  }
}
```

Prevents duplicate alerts for ongoing issues.

### Security

The systemd service runs with:
- Dedicated `mail-monitor` user (no privileges)
- No device access (`PrivateDevices=true`)
- No new privileges (`NoNewPrivileges=true`)
- Network access only (`RestrictAddressFamilies=AF_INET`)
- Read-only root filesystem (`ProtectSystem=strict`)
- Isolated state directory (`StateDirectory=mail-monitor`)

## Integration with Existing Prometheus Metrics

Your mail server already exposes metrics on port 5034. Consider:

1. **Grafana Dashboard** - Visualize mail-monitor results alongside server metrics
2. **Alertmanager** - Route Prometheus alerts to same ntfy.sh topic
3. **Combined Monitoring** - External (mail-monitor) + Internal (Prometheus)

Example query for correlation:
```promql
# Mail queue depth when monitoring detects issues
postfix_showq_count{} [5m]
```

## Advanced Configuration

### Multiple Mail Servers

```nix
services.mail-monitor-primary = {
  enable = true;
  smtp.host = "mail1.example.com";
  imap.host = "mail1.example.com";
  credentials.passwordFile = "/run/secrets/mail1-password";
  ntfy.topic = "mail1-alerts";
};

services.mail-monitor-backup = {
  enable = true;
  smtp.host = "mail2.example.com";
  imap.host = "mail2.example.com";
  credentials.passwordFile = "/run/secrets/mail2-password";
  ntfy.topic = "mail2-alerts";
};
```

### Custom Intervals by Time of Day

Use systemd calendar expressions:

```nix
# Override timer with custom calendar
systemd.timers.mail-monitor.timerConfig.OnCalendar = [
  "*-*-* 08..20:00,15,30,45:00"  # Every 15min during business hours
  "*-*-* 00,01,02,03,04,05,06,07,21,22,23:00:00"  # Hourly at night
];
```

## Support

- **Issues**: https://github.com/fudoniten/nix-mail-server/issues
- **Logs**: `journalctl -u mail-monitor.service`
- **Status**: `systemctl status mail-monitor.service`

## License

MIT License - See LICENSE file for details.
