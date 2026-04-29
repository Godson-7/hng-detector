import time
import threading
import psutil
from datetime import datetime
from flask import Flask, jsonify, render_template_string

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HNG Anomaly Detector</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }
        h1 { color: #58a6ff; margin-bottom: 20px; font-size: 1.5rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
        .card h2 { color: #58a6ff; font-size: 0.9rem; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }
        .metric { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 0.85rem; }
        .metric .label { color: #8b949e; }
        .metric .value { color: #e6edf3; font-weight: bold; }
        .value.danger { color: #f85149; }
        .value.warning { color: #d29922; }
        .value.ok { color: #3fb950; }
        table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
        th { color: #8b949e; text-align: left; padding: 6px 8px; border-bottom: 1px solid #30363d; }
        td { padding: 6px 8px; border-bottom: 1px solid #21262d; }
        .banned-ip { color: #f85149; }
        .status-bar { display: flex; gap: 20px; margin-bottom: 20px; font-size: 0.8rem; }
        .status-bar span { color: #8b949e; }
        .status-bar strong { color: #3fb950; }
        .refresh-indicator { float: right; color: #8b949e; font-size: 0.75rem; }
    </style>
</head>
<body>
    <h1>🛡️ HNG Anomaly Detection Engine <span class="refresh-indicator" id="last-update"></span></h1>

    <div class="status-bar">
        <span>Status: <strong id="status">LIVE</strong></span>
        <span>Uptime: <strong id="uptime"></strong></span>
        <span>Detector: <strong>ACTIVE</strong></span>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Traffic</h2>
            <div class="metric"><span class="label">Global req/s</span><span class="value" id="global-rate">-</span></div>
            <div class="metric"><span class="label">Baseline Mean</span><span class="value" id="baseline-mean">-</span></div>
            <div class="metric"><span class="label">Baseline Stddev</span><span class="value" id="baseline-stddev">-</span></div>
            <div class="metric"><span class="label">Active Bans</span><span class="value danger" id="ban-count">-</span></div>
        </div>
        <div class="card">
            <h2>System</h2>
            <div class="metric"><span class="label">CPU Usage</span><span class="value" id="cpu">-</span></div>
            <div class="metric"><span class="label">Memory Usage</span><span class="value" id="memory">-</span></div>
            <div class="metric"><span class="label">Memory Used</span><span class="value" id="memory-used">-</span></div>
            <div class="metric"><span class="label">Memory Total</span><span class="value" id="memory-total">-</span></div>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Banned IPs</h2>
            <table>
                <thead><tr><th>IP</th><th>Rate</th><th>Duration</th><th>Banned At</th></tr></thead>
                <tbody id="banned-table"><tr><td colspan="4" style="color:#8b949e">No active bans</td></tr></tbody>
            </table>
        </div>
        <div class="card">
            <h2>Top 10 Source IPs</h2>
            <table>
                <thead><tr><th>IP</th><th>Total Requests</th></tr></thead>
                <tbody id="top-ips-table"><tr><td colspan="2" style="color:#8b949e">No data yet</td></tr></tbody>
            </table>
        </div>
    </div>

    <script>
        const startTime = Date.now();

        function formatUptime(seconds) {
            const h = Math.floor(seconds / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            const s = Math.floor(seconds % 60);
            return `${h}h ${m}m ${s}s`;
        }

        function colorRate(rate, mean) {
            if (mean <= 0) return 'value';
            const ratio = rate / mean;
            if (ratio > 5) return 'value danger';
            if (ratio > 2) return 'value warning';
            return 'value ok';
        }

        async function refresh() {
            try {
                const resp = await fetch('/api/metrics');
                const data = await resp.json();

                document.getElementById('global-rate').textContent = data.global_rate.toFixed(3) + ' req/s';
                document.getElementById('baseline-mean').textContent = data.baseline_mean.toFixed(3) + ' req/s';
                document.getElementById('baseline-stddev').textContent = data.baseline_stddev.toFixed(3);
                document.getElementById('ban-count').textContent = data.ban_count;
                document.getElementById('cpu').textContent = data.cpu_percent.toFixed(1) + '%';
                document.getElementById('memory').textContent = data.memory_percent.toFixed(1) + '%';
                document.getElementById('memory-used').textContent = (data.memory_used_mb).toFixed(0) + ' MB';
                document.getElementById('memory-total').textContent = (data.memory_total_mb).toFixed(0) + ' MB';
                document.getElementById('uptime').textContent = formatUptime(data.uptime_seconds);
                document.getElementById('last-update').textContent = 'Updated: ' + new Date().toLocaleTimeString();

                // Banned IPs table
                const bannedTbody = document.getElementById('banned-table');
                if (data.banned_ips.length === 0) {
                    bannedTbody.innerHTML = '<tr><td colspan="4" style="color:#8b949e">No active bans</td></tr>';
                } else {
                    bannedTbody.innerHTML = data.banned_ips.map(b =>
                        `<tr>
                            <td class="banned-ip">${b.ip}</td>
                            <td>${b.rate.toFixed(3)}</td>
                            <td>${b.duration === -1 ? 'permanent' : b.duration + 's'}</td>
                            <td>${b.banned_at}</td>
                        </tr>`
                    ).join('');
                }

                // Top IPs table
                const topTbody = document.getElementById('top-ips-table');
                if (data.top_ips.length === 0) {
                    topTbody.innerHTML = '<tr><td colspan="2" style="color:#8b949e">No data yet</td></tr>';
                } else {
                    topTbody.innerHTML = data.top_ips.map(([ip, count]) =>
                        `<tr><td>${ip}</td><td>${count}</td></tr>`
                    ).join('');
                }

            } catch (e) {
                console.error('Refresh error:', e);
            }
        }

        refresh();
        setInterval(refresh, 3000);
    </script>
</body>
</html>
"""

class Dashboard:
    def __init__(self, config, monitor, baseline, blocker):
        self.monitor = monitor
        self.baseline = baseline
        self.blocker = blocker
        self.port = config['dashboard_port']
        self.start_time = time.time()
        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):
        @self.app.route('/')
        def index():
            return render_template_string(DASHBOARD_HTML)

        @self.app.route('/api/metrics')
        def metrics():
            mean, stddev = self.baseline.get_baseline()
            banned = self.blocker.get_banned_ips()
            mem = psutil.virtual_memory()

            banned_list = []
            for ip, info in banned.items():
                banned_list.append({
                    'ip': ip,
                    'rate': info.get('rate', 0),
                    'duration': info.get('duration', -1),
                    'banned_at': info['banned_at'].strftime('%H:%M:%S') if info.get('banned_at') else '-'
                })

            return jsonify({
                'global_rate': self.monitor.get_global_rate(),
                'baseline_mean': mean,
                'baseline_stddev': stddev,
                'ban_count': len(banned),
                'banned_ips': banned_list,
                'top_ips': self.monitor.get_top_ips(10),
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': mem.percent,
                'memory_used_mb': mem.used / 1024 / 1024,
                'memory_total_mb': mem.total / 1024 / 1024,
                'uptime_seconds': time.time() - self.start_time
            })

    def start(self):
        t = threading.Thread(
            target=lambda: self.app.run(host='0.0.0.0', port=self.port, debug=False),
            daemon=True,
            name="dashboard"
        )
        t.start()
        print(f"[Dashboard] Started on port {self.port}")
        return t
