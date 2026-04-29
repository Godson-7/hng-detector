import time
import threading
from datetime import datetime

class AnomalyDetector:
    def __init__(self, config, monitor, baseline, blocker, notifier):
        self.monitor = monitor
        self.baseline = baseline
        self.blocker = blocker
        self.notifier = notifier

        self.zscore_threshold = config['zscore_threshold']
        self.rate_multiplier = config['rate_multiplier_threshold']
        self.error_multiplier = config['error_rate_multiplier']

        self.running = True

        # Track already-flagged IPs to avoid duplicate alerts
        self.flagged_ips = set()
        self.lock = threading.Lock()

    def _compute_zscore(self, current_rate, mean, stddev):
        """Z-score: how many stddevs above mean is the current rate."""
        return (current_rate - mean) / stddev

    def _check_ip(self, ip, mean, stddev):
        """
        Check a single IP for anomaly.
        Two conditions — whichever fires first:
          1. Z-score > threshold
          2. Rate > 5x baseline mean
        Also tightens thresholds if IP has high error rate.
        """
        ip_rate = self.monitor.get_ip_rate(ip)
        if ip_rate <= 0:
            return

        # Tighten thresholds if IP has elevated error rate
        ip_error_rate = self.monitor.get_ip_error_rate(ip)
        baseline_error_rate = max(self.baseline.baseline_error_rate, 0.01)
        tightened = ip_error_rate >= (self.error_multiplier * baseline_error_rate)

        effective_zscore_threshold = self.zscore_threshold * 0.7 if tightened else self.zscore_threshold
        effective_rate_multiplier = self.rate_multiplier * 0.7 if tightened else self.rate_multiplier

        zscore = self._compute_zscore(ip_rate, mean, stddev)
        rate_breach = ip_rate > (effective_rate_multiplier * mean)
        zscore_breach = zscore > effective_zscore_threshold

        if not (zscore_breach or rate_breach):
            return

        with self.lock:
            if ip in self.flagged_ips:
                return
            self.flagged_ips.add(ip)

        # Determine which condition fired
        condition = []
        if zscore_breach:
            condition.append(f"zscore={zscore:.2f}>{effective_zscore_threshold}")
        if rate_breach:
            condition.append(f"rate={ip_rate:.2f}>{effective_rate_multiplier:.1f}x_mean")
        if tightened:
            condition.append("error_surge=true")
        condition_str = " | ".join(condition)

        print(f"[Detector] IP anomaly: {ip} | {condition_str} | rate={ip_rate:.3f} | mean={mean:.3f}")

        # Block and alert
        duration = self.blocker.ban(ip, condition_str, ip_rate, mean)
        self.notifier.send_ban_alert(ip, condition_str, ip_rate, mean, stddev, duration)

    def _check_global(self, mean, stddev):
        """
        Check global traffic rate for anomaly.
        Global anomaly = Slack alert only, no IP block.
        """
        global_rate = self.monitor.get_global_rate()
        if global_rate <= 0:
            return

        zscore = self._compute_zscore(global_rate, mean, stddev)
        rate_breach = global_rate > (self.rate_multiplier * mean)
        zscore_breach = zscore > self.zscore_threshold

        if not (zscore_breach or rate_breach):
            return

        condition = []
        if zscore_breach:
            condition.append(f"zscore={zscore:.2f}>{self.zscore_threshold}")
        if rate_breach:
            condition.append(f"rate={global_rate:.2f}>{self.rate_multiplier}x_mean")
        condition_str = " | ".join(condition)

        print(f"[Detector] GLOBAL anomaly: {condition_str} | rate={global_rate:.3f} | mean={mean:.3f}")
        self.notifier.send_global_alert(condition_str, global_rate, mean, stddev)

    def untrack_ip(self, ip):
        """Remove IP from flagged set after ban expires (called by unbanner)."""
        with self.lock:
            self.flagged_ips.discard(ip)

    def run(self):
        """
        Main detection loop — runs every second.
        Checks all active IPs and global rate.
        """
        print("[Detector] Started.")
        while self.running:
            mean, stddev = self.baseline.get_baseline()

            # Check global traffic
            self._check_global(mean, stddev)

            # Check each active IP
            active_ips = self.monitor.get_active_ips()
            for ip in active_ips:
                if not self.blocker.is_banned(ip):
                    self._check_ip(ip, mean, stddev)

            time.sleep(1)

    def start(self):
        t = threading.Thread(target=self.run, daemon=True, name="anomaly-detector")
        t.start()
        return t

    def stop(self):
        self.running = False
