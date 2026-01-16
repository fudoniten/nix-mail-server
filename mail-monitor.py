#!/usr/bin/env python3
"""
Mail Server Monitoring Script

Tests mail server functionality:
- IMAP authentication
- SMTP authentication
- Email sending
- Email receiving
- Sends notifications to ntfy.sh on failures
"""

import argparse
import imaplib
import json
import smtplib
import ssl
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid
from pathlib import Path
from typing import Optional, Dict, Any


class MailMonitor:
    """Monitor mail server health with comprehensive tests"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.state_file = Path(config.get('state_file', '/var/lib/mail-monitor/state.json'))
        self.state = self._load_state()
        self.test_results = {
            'imap_auth': False,
            'smtp_auth': False,
            'send': False,
            'receive': False,
            'timestamp': datetime.now().isoformat()
        }

    def _load_state(self) -> Dict[str, Any]:
        """Load previous state from file"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load state file: {e}", file=sys.stderr)
        return {'last_status': 'unknown', 'last_failure': None}

    def _save_state(self):
        """Save current state to file"""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save state file: {e}", file=sys.stderr)

    def test_imap_auth(self) -> tuple[bool, Optional[str]]:
        """Test IMAP authentication"""
        try:
            context = ssl.create_default_context()
            with imaplib.IMAP4_SSL(
                self.config['imap_host'],
                self.config.get('imap_port', 993),
                ssl_context=context
            ) as imap:
                imap.login(self.config['username'], self.config['password'])
                return True, None
        except Exception as e:
            return False, f"IMAP auth failed: {str(e)}"

    def test_smtp_auth(self) -> tuple[bool, Optional[str]]:
        """Test SMTP authentication"""
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(
                self.config['smtp_host'],
                self.config.get('smtp_port', 587)
            ) as smtp:
                smtp.starttls(context=context)
                smtp.login(self.config['username'], self.config['password'])
                return True, None
        except Exception as e:
            return False, f"SMTP auth failed: {str(e)}"

    def send_test_email(self) -> tuple[bool, Optional[str], Optional[str]]:
        """Send a test email with unique ID"""
        try:
            msg_id = make_msgid(domain=self.config['smtp_host'])

            msg = MIMEText(
                f"Mail server monitoring test\n"
                f"Sent at: {datetime.now().isoformat()}\n"
                f"Message-ID: {msg_id}\n",
                'plain'
            )
            msg['Subject'] = f"Mail Monitor Test - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            msg['From'] = formataddr(('Mail Monitor', self.config['username']))
            msg['To'] = self.config['test_recipient']
            msg['Message-ID'] = msg_id
            msg['X-Mail-Monitor'] = 'true'

            context = ssl.create_default_context()
            with smtplib.SMTP(
                self.config['smtp_host'],
                self.config.get('smtp_port', 587)
            ) as smtp:
                smtp.starttls(context=context)
                smtp.login(self.config['username'], self.config['password'])
                smtp.send_message(msg)

            return True, None, msg_id
        except Exception as e:
            return False, f"Failed to send test email: {str(e)}", None

    def check_test_email(self, msg_id: str, timeout: int = 60) -> tuple[bool, Optional[str]]:
        """Check if test email was received"""
        start_time = time.time()

        try:
            context = ssl.create_default_context()

            while time.time() - start_time < timeout:
                try:
                    with imaplib.IMAP4_SSL(
                        self.config['imap_host'],
                        self.config.get('imap_port', 993),
                        ssl_context=context
                    ) as imap:
                        imap.login(self.config['username'], self.config['password'])
                        imap.select('INBOX')

                        # Search for our test email by Message-ID
                        # Clean up the message ID for search (remove < >)
                        search_id = msg_id.strip('<>')
                        status, messages = imap.search(None, f'HEADER Message-ID "{search_id}"')

                        if status == 'OK' and messages[0]:
                            # Found the email, delete it
                            msg_nums = messages[0].split()
                            if msg_nums:
                                for num in msg_nums:
                                    imap.store(num, '+FLAGS', '\\Deleted')
                                imap.expunge()

                                delivery_time = time.time() - start_time
                                return True, f"Email delivered in {delivery_time:.1f}s"

                        # Not found yet, wait a bit before retrying
                        time.sleep(2)

                except Exception as e:
                    # Temporary error, continue retrying
                    time.sleep(2)

            return False, f"Email not received within {timeout}s timeout"

        except Exception as e:
            return False, f"Failed to check for test email: {str(e)}"

    def cleanup_old_test_emails(self):
        """Clean up old test emails from inbox"""
        try:
            context = ssl.create_default_context()
            with imaplib.IMAP4_SSL(
                self.config['imap_host'],
                self.config.get('imap_port', 993),
                ssl_context=context
            ) as imap:
                imap.login(self.config['username'], self.config['password'])
                imap.select('INBOX')

                # Search for old monitoring emails
                status, messages = imap.search(None, 'HEADER X-Mail-Monitor "true"')

                if status == 'OK' and messages[0]:
                    msg_nums = messages[0].split()
                    for num in msg_nums:
                        imap.store(num, '+FLAGS', '\\Deleted')
                    imap.expunge()
        except Exception:
            # Non-critical, just log and continue
            pass

    def send_notification(self, title: str, message: str, priority: str = 'default', tags: list = None):
        """Send notification to ntfy.sh"""
        if not self.config.get('ntfy_topic'):
            return

        try:
            url = f"{self.config.get('ntfy_server', 'https://ntfy.sh')}/{self.config['ntfy_topic']}"
            headers = {
                'Title': title,
                'Priority': priority,
            }
            if tags:
                headers['Tags'] = ','.join(tags)

            req = urllib.request.Request(
                url,
                data=message.encode('utf-8'),
                headers=headers,
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status != 200:
                    print(f"Warning: ntfy.sh returned status {response.status}", file=sys.stderr)

        except Exception as e:
            print(f"Warning: Failed to send notification: {e}", file=sys.stderr)

    def run_tests(self) -> bool:
        """Run all monitoring tests"""
        failures = []

        # Test IMAP auth
        success, error = self.test_imap_auth()
        self.test_results['imap_auth'] = success
        if not success:
            failures.append(error)
            print(f"❌ IMAP Auth: {error}")
        else:
            print("✓ IMAP Auth: OK")

        # Test SMTP auth
        success, error = self.test_smtp_auth()
        self.test_results['smtp_auth'] = success
        if not success:
            failures.append(error)
            print(f"❌ SMTP Auth: {error}")
        else:
            print("✓ SMTP Auth: OK")

        # If auth tests pass, test send/receive
        if self.test_results['smtp_auth'] and self.test_results['imap_auth']:
            # Send test email
            success, error, msg_id = self.send_test_email()
            self.test_results['send'] = success
            if not success:
                failures.append(error)
                print(f"❌ Send Test: {error}")
            else:
                print(f"✓ Send Test: OK (Message-ID: {msg_id})")

                # Check if email was received
                if msg_id:
                    success, result = self.check_test_email(msg_id, timeout=self.config.get('receive_timeout', 60))
                    self.test_results['receive'] = success
                    if not success:
                        failures.append(result)
                        print(f"❌ Receive Test: {result}")
                    else:
                        print(f"✓ Receive Test: {result}")

                        # Cleanup old test emails
                        self.cleanup_old_test_emails()

        # Determine overall status
        all_passed = all(self.test_results.values())

        # Send notifications based on state changes
        current_status = 'healthy' if all_passed else 'unhealthy'
        previous_status = self.state.get('last_status', 'unknown')

        if current_status != previous_status:
            if current_status == 'unhealthy':
                # New failure
                self.send_notification(
                    '🚨 Mail Server Alert',
                    f"Mail server monitoring detected failures:\n\n" + "\n".join(f"• {f}" for f in failures),
                    priority='high',
                    tags=['rotating_light', 'email']
                )
            elif previous_status == 'unhealthy':
                # Recovery
                self.send_notification(
                    '✅ Mail Server Recovered',
                    'Mail server monitoring: all tests passing',
                    priority='default',
                    tags=['white_check_mark', 'email']
                )

        # Update state
        self.state['last_status'] = current_status
        if failures:
            self.state['last_failure'] = {
                'timestamp': datetime.now().isoformat(),
                'failures': failures
            }
        self._save_state()

        return all_passed


def main():
    parser = argparse.ArgumentParser(description='Monitor mail server health')
    parser.add_argument('--config', type=Path, help='Config file (JSON)')
    parser.add_argument('--smtp-host', help='SMTP server hostname')
    parser.add_argument('--smtp-port', type=int, default=587, help='SMTP port (default: 587)')
    parser.add_argument('--imap-host', help='IMAP server hostname')
    parser.add_argument('--imap-port', type=int, default=993, help='IMAP port (default: 993)')
    parser.add_argument('--username', help='Email username')
    parser.add_argument('--password', help='Email password')
    parser.add_argument('--test-recipient', help='Test email recipient (default: same as username)')
    parser.add_argument('--ntfy-topic', help='Ntfy.sh topic')
    parser.add_argument('--ntfy-server', default='https://ntfy.sh', help='Ntfy.sh server URL')
    parser.add_argument('--state-file', type=Path, help='State file path')
    parser.add_argument('--receive-timeout', type=int, default=60, help='Receive timeout in seconds')

    args = parser.parse_args()

    # Load config from file if provided
    config = {}
    if args.config and args.config.exists():
        with open(args.config, 'r') as f:
            config = json.load(f)

    # Override with command line arguments
    for key in ['smtp_host', 'smtp_port', 'imap_host', 'imap_port', 'username',
                'password', 'test_recipient', 'ntfy_topic', 'ntfy_server',
                'state_file', 'receive_timeout']:
        value = getattr(args, key)
        if value is not None:
            config[key] = value

    # Set defaults
    if 'test_recipient' not in config:
        config['test_recipient'] = config.get('username')

    # Validate required fields
    required = ['smtp_host', 'imap_host', 'username', 'password']
    missing = [f for f in required if f not in config]
    if missing:
        print(f"Error: Missing required configuration: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    # Run monitoring
    monitor = MailMonitor(config)
    success = monitor.run_tests()

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
