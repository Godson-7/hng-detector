import requests
import threading
from datetime import datetime

class Notifier:
    def __init__(self, config):
        self.webhook_url = config['slack_webhook_url']
        self.lock = threading.Lock()

    def _send(self, payload):
        """Send payload to Slack webhook in a background thread."""
        def _post():
            try:
                resp = requests.post(self.webhook_url, json=payload, timeout=10)
                if resp.status_code != 200:
                    print(f"[Notifier] Slack error: {resp.status_code} {resp.text}")
            except Exception as e:
                print(f"[Notifier] Request failed: {e}")

        t = threading.Thread(target=_post, daemon=True)
        t.start()

    def send_ban_alert(self, ip, condition, rate, baseline_mean, baseline_stddev, duration):
        """Send per-IP ban notification to Slack."""
        duration_str = "permanent" if duration == -1 else f"{duration}s"
        ts = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

        payload = {
            "text": (
                f":rotating_light: *IP BANNED*\n"
                f">*IP:* `{ip}`\n"
                f">*Condition:* {condition}\n"
                f">*Current Rate:* {rate:.3f} req/s\n"
                f">*Baseline Mean:* {baseline_mean:.3f} req/s\n"
                f">*Baseline Stddev:* {baseline_stddev:.3f}\n"
                f">*Ban Duration:* {duration_str}\n"
                f">*Timestamp:* {ts}"
            )
        }
        print(f"[Notifier] Sending ban alert for {ip}")
        self._send(payload)

    def send_unban_alert(self, ip, condition, rate, baseline, duration, next_duration):
        """Send unban notification to Slack."""
        ts = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        duration_str = f"{duration}s"

        payload = {
            "text": (
                f":white_check_mark: *IP UNBANNED*\n"
                f">*IP:* `{ip}`\n"
                f">*Original Condition:* {condition}\n"
                f">*Ban Duration Served:* {duration_str}\n"
                f">*Next Ban Duration If Re-offends:* {next_duration}\n"
                f">*Timestamp:* {ts}"
            )
        }
        print(f"[Notifier] Sending unban alert for {ip}")
        self._send(payload)

    def send_global_alert(self, condition, rate, baseline_mean, baseline_stddev):
        """Send global traffic anomaly notification to Slack."""
        ts = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

        payload = {
            "text": (
                f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
                f">*Condition:* {condition}\n"
                f">*Current Global Rate:* {rate:.3f} req/s\n"
                f">*Baseline Mean:* {baseline_mean:.3f} req/s\n"
                f">*Baseline Stddev:* {baseline_stddev:.3f}\n"
                f">*Action:* Monitor only — no IP block\n"
                f">*Timestamp:* {ts}"
            )
        }
        print(f"[Notifier] Sending global anomaly alert")
        self._send(payload)
