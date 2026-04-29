import time
import math
import threading
from datetime import datetime

class BaselineEngine:
    def __init__(self, config, monitor):
        self.monitor = monitor
        self.recalc_interval = config['baseline_recalc_interval']
        self.mean_floor = config['mean_floor']
        self.stddev_floor = config['stddev_floor']
        self.audit_log_path = config['audit_log_path']

        # Current baseline values
        self.effective_mean = config['mean_floor']
        self.effective_stddev = config['stddev_floor']

        # Per-hour slots: {hour: [per_second_counts]}
        self.hour_slots = {}

        # Per-IP baseline error rate
        self.baseline_error_rate = 0.0

        self.lock = threading.Lock()
        self.running = True

    def _compute_stats(self, data):
        """Compute mean and stddev from a list of numbers."""
        if not data:
            return self.mean_floor, self.stddev_floor

        n = len(data)
        mean = sum(data) / n

        if n < 2:
            return max(mean, self.mean_floor), self.stddev_floor

        variance = sum((x - mean) ** 2 for x in data) / (n - 1)
        stddev = math.sqrt(variance)

        return max(mean, self.mean_floor), max(stddev, self.stddev_floor)

    def recalculate(self):
        """
        Recalculate baseline from rolling window.
        Prefer current hour's data if it has enough samples (>= 120).
        Fall back to full 30-minute window otherwise.
        """
        now = datetime.now()
        current_hour = now.hour

        # Record current hour's recent counts
        counts = self.monitor.get_per_second_counts()

        with self.lock:
            # Store into hourly slot
            if current_hour not in self.hour_slots:
                self.hour_slots[current_hour] = []
            self.hour_slots[current_hour].extend(counts[-60:])

            # Keep only last 1800 samples per hour slot
            self.hour_slots[current_hour] = self.hour_slots[current_hour][-1800:]

            # Prefer current hour if enough data
            current_hour_data = self.hour_slots.get(current_hour, [])
            if len(current_hour_data) >= 120:
                data_to_use = current_hour_data
                source = f"hour_{current_hour}"
            else:
                data_to_use = counts
                source = "rolling_30min"

            mean, stddev = self._compute_stats(data_to_use)
            self.effective_mean = mean
            self.effective_stddev = stddev

        # Write audit log entry
        self._audit(current_hour, mean, stddev, source, len(data_to_use))
        print(f"[Baseline] Recalculated — mean={mean:.3f} stddev={stddev:.3f} source={source} samples={len(data_to_use)}")

    def _audit(self, hour, mean, stddev, source, samples):
        """Write baseline recalculation to audit log."""
        ts = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        line = (
            f"[{ts}] BASELINE_RECALC ip=global | "
            f"condition=recalc | "
            f"rate={self.monitor.get_global_rate():.3f} | "
            f"baseline=mean:{mean:.3f},stddev:{stddev:.3f} | "
            f"source={source} samples={samples}\n"
        )
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(line)
        except Exception as e:
            print(f"[Baseline] Audit log error: {e}")

    def get_baseline(self):
        """Return current effective mean and stddev."""
        with self.lock:
            return self.effective_mean, self.effective_stddev

    def record_tick(self):
        """Called every second to snapshot current global req/s."""
        rate = self.monitor.get_global_rate()
        self.monitor.record_per_second_count(rate)

    def run(self):
        """
        Main loop:
        - Every second: record a per-second snapshot
        - Every recalc_interval seconds: recalculate baseline
        """
        print("[Baseline] Started.")
        tick_count = 0
        while self.running:
            self.record_tick()
            tick_count += 1
            if tick_count >= self.recalc_interval:
                self.recalculate()
                tick_count = 0
            time.sleep(1)

    def start(self):
        t = threading.Thread(target=self.run, daemon=True, name="baseline-engine")
        t.start()
        return t

    def stop(self):
        self.running = False
