import subprocess
import threading
from datetime import datetime

class Blocker:
    def __init__(self, config, audit_log_path):
        self.audit_log_path = audit_log_path
        self.unban_schedule = config['unban_schedule']
        self.banned_ips = {}
        self.lock = threading.Lock()

    def _run_iptables(self, action, ip):
        """Run iptables without sudo — container has NET_ADMIN cap."""
        try:
            cmd = ['iptables', f'-{action}', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[Blocker] iptables error: {result.stderr.strip()}")
            return result.returncode == 0
        except Exception as e:
            print(f"[Blocker] iptables exception: {e}")
            return False

    def _get_duration(self, ban_count):
        schedule = self.unban_schedule
        idx = min(ban_count, len(schedule) - 1)
        return schedule[idx]

    def ban(self, ip, condition, rate, baseline_mean):
        with self.lock:
            ban_count = 0
            if ip in self.banned_ips:
                ban_count = self.banned_ips[ip].get('ban_count', 0)
            duration = self._get_duration(ban_count)
            self.banned_ips[ip] = {
                'condition': condition,
                'rate': rate,
                'baseline': baseline_mean,
                'ban_count': ban_count + 1,
                'banned_at': datetime.now(),
                'duration': duration
            }
        success = self._run_iptables('A', ip)
        status = "success" if success else "failed"
        duration_str = "permanent" if duration == -1 else f"{duration}s"
        print(f"[Blocker] Banned {ip} | duration={duration_str} | iptables={status}")
        self._audit_ban(ip, condition, rate, baseline_mean, duration_str)
        return duration

    def unban(self, ip):
        self._run_iptables('D', ip)
        with self.lock:
            info = self.banned_ips.pop(ip, {})
        duration_str = "permanent" if info.get('duration') == -1 else f"{info.get('duration', 0)}s"
        print(f"[Blocker] Unbanned {ip}")
        self._audit_unban(ip, info, duration_str)
        return info

    def is_banned(self, ip):
        with self.lock:
            return ip in self.banned_ips

    def get_banned_ips(self):
        with self.lock:
            return dict(self.banned_ips)

    def get_ban_info(self, ip):
        with self.lock:
            return self.banned_ips.get(ip, {})

    def _audit_ban(self, ip, condition, rate, baseline, duration_str):
        ts = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        line = (
            f"[{ts}] BAN ip={ip} | "
            f"condition={condition} | "
            f"rate={rate:.3f} | "
            f"baseline={baseline:.3f} | "
            f"duration={duration_str}\n"
        )
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(line)
        except Exception as e:
            print(f"[Blocker] Audit log error: {e}")

    def _audit_unban(self, ip, info, duration_str):
        ts = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        line = (
            f"[{ts}] UNBAN ip={ip} | "
            f"condition={info.get('condition', 'unknown')} | "
            f"rate={info.get('rate', 0):.3f} | "
            f"baseline={info.get('baseline', 0):.3f} | "
            f"duration={duration_str}\n"
        )
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(line)
        except Exception as e:
            print(f"[Blocker] Audit log error: {e}")
