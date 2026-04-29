import json
import time
import threading
from collections import deque
from datetime import datetime

class LogMonitor:
    def __init__(self, config):
        self.log_path = config['log_path']
        self.window_seconds = config['sliding_window_seconds']
        
        # Shared state - thread safe via lock
        self.lock = threading.Lock()
        
        # Per-IP sliding windows: {ip: deque of timestamps}
        self.ip_windows = {}
        
        # Global sliding window: deque of timestamps
        self.global_window = deque()
        
        # Per-IP error tracking: {ip: deque of (timestamp, status)}
        self.ip_error_windows = {}
        
        # Per-second global counts for baseline (last 30 min = 1800 entries)
        self.per_second_counts = deque(maxlen=1800)
        
        # Top IPs tracking
        self.ip_total_counts = {}
        
        # Running flag
        self.running = True

    def _parse_line(self, line):
        """Parse a JSON log line from nginx."""
        line = line.strip()
        if not line:
            return None
        try:
            entry = json.loads(line)
            # Validate required fields exist
            if 'source_ip' not in entry or 'status' not in entry:
                return None
            # Clean up source_ip (X-Forwarded-For can have multiple IPs)
            ip = entry['source_ip'].split(',')[0].strip()
            if not ip or ip == '-':
                ip = '0.0.0.0'
            entry['source_ip'] = ip
            return entry
        except (json.JSONDecodeError, KeyError):
            return None

    def _evict_old(self, dq, cutoff):
        """Remove timestamps older than cutoff from left of deque."""
        while dq and dq[0] < cutoff:
            dq.popleft()

    def record_request(self, entry):
        """Record a parsed request into all sliding windows."""
        now = time.time()
        cutoff = now - self.window_seconds
        ip = entry['source_ip']
        status = int(entry.get('status', 200))

        with self.lock:
            # Global window
            self._evict_old(self.global_window, cutoff)
            self.global_window.append(now)

            # Per-IP window
            if ip not in self.ip_windows:
                self.ip_windows[ip] = deque()
            self._evict_old(self.ip_windows[ip], cutoff)
            self.ip_windows[ip].append(now)

            # Per-IP error window
            if status >= 400:
                if ip not in self.ip_error_windows:
                    self.ip_error_windows[ip] = deque()
                self._evict_old(self.ip_error_windows[ip], cutoff)
                self.ip_error_windows[ip].append(now)

            # Total count per IP for dashboard top-10
            self.ip_total_counts[ip] = self.ip_total_counts.get(ip, 0) + 1

    def get_global_rate(self):
        """Current global requests per second."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self.lock:
            self._evict_old(self.global_window, cutoff)
            return len(self.global_window) / self.window_seconds

    def get_ip_rate(self, ip):
        """Current requests per second for a specific IP."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self.lock:
            if ip not in self.ip_windows:
                return 0.0
            self._evict_old(self.ip_windows[ip], cutoff)
            return len(self.ip_windows[ip]) / self.window_seconds

    def get_ip_error_rate(self, ip):
        """Current 4xx/5xx rate for a specific IP."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self.lock:
            if ip not in self.ip_error_windows:
                return 0.0
            self._evict_old(self.ip_error_windows[ip], cutoff)
            return len(self.ip_error_windows[ip]) / self.window_seconds

    def get_active_ips(self):
        """Return list of IPs seen in the current window."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self.lock:
            active = []
            for ip, dq in self.ip_windows.items():
                self._evict_old(dq, cutoff)
                if dq:
                    active.append(ip)
            return active

    def get_top_ips(self, n=10):
        """Return top N IPs by total request count."""
        with self.lock:
            sorted_ips = sorted(
                self.ip_total_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ips[:n]

    def record_per_second_count(self, count):
        """Called every second by baseline to record global req/s."""
        with self.lock:
            self.per_second_counts.append(count)

    def get_per_second_counts(self):
        """Return copy of per-second counts for baseline calculation."""
        with self.lock:
            return list(self.per_second_counts)

    def tail_log(self):
        """
        Continuously tail the nginx log file.
        Handles file rotation and missing file gracefully.
        """
        print(f"[Monitor] Starting log tail: {self.log_path}")
        while self.running:
            try:
                with open(self.log_path, 'r') as f:
                    # Seek to end of file on first open
                    f.seek(0, 2)
                    while self.running:
                        line = f.readline()
                        if line:
                            entry = self._parse_line(line)
                            if entry:
                                self.record_request(entry)
                        else:
                            time.sleep(0.05)
            except FileNotFoundError:
                print(f"[Monitor] Log file not found, retrying in 5s...")
                time.sleep(5)
            except Exception as e:
                print(f"[Monitor] Error: {e}, retrying in 2s...")
                time.sleep(2)

    def start(self):
        """Start tailing in a background thread."""
        t = threading.Thread(target=self.tail_log, daemon=True, name="log-monitor")
        t.start()
        print("[Monitor] Started.")
        return t

    def stop(self):
        self.running = False
