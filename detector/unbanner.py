import time
import threading
from datetime import datetime

class Unbanner:
    def __init__(self, blocker, notifier, detector):
        self.blocker = blocker
        self.notifier = notifier
        self.detector = detector
        self.running = True

    def run(self):
        """
        Every 10 seconds, check all banned IPs.
        If their ban duration has elapsed, unban them.
        Permanent bans (duration == -1) are never unbanned.
        """
        print("[Unbanner] Started.")
        while self.running:
            now = datetime.now()
            banned = self.blocker.get_banned_ips()

            for ip, info in banned.items():
                duration = info.get('duration', -1)

                # Skip permanent bans
                if duration == -1:
                    continue

                banned_at = info.get('banned_at')
                if not banned_at:
                    continue

                elapsed = (now - banned_at).total_seconds()

                if elapsed >= duration:
                    print(f"[Unbanner] Releasing {ip} after {duration}s")
                    ban_info = self.blocker.unban(ip)

                    # Determine next ban duration for notification
                    ban_count = info.get('ban_count', 1)
                    schedule = self.blocker.unban_schedule
                    next_idx = min(ban_count, len(schedule) - 1)
                    next_duration = schedule[next_idx]
                    next_str = "permanent" if next_duration == -1 else f"{next_duration}s"

                    # Notify Slack
                    self.notifier.send_unban_alert(
                        ip=ip,
                        condition=info.get('condition', 'unknown'),
                        rate=info.get('rate', 0),
                        baseline=info.get('baseline', 0),
                        duration=duration,
                        next_duration=next_str
                    )

                    # Allow detector to re-flag this IP if it misbehaves again
                    self.detector.untrack_ip(ip)

            time.sleep(10)

    def start(self):
        t = threading.Thread(target=self.run, daemon=True, name="unbanner")
        t.start()
        return t

    def stop(self):
        self.running = False
