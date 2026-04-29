import time
import signal
import sys
import yaml
from monitor import LogMonitor
from baseline import BaselineEngine
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard

def load_config(path='config.yaml'):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def main():
    print("[Main] Starting HNG Anomaly Detection Engine...")
    config = load_config()

    # Initialize all components
    monitor  = LogMonitor(config)
    baseline = BaselineEngine(config, monitor)
    blocker  = Blocker(config, config['audit_log_path'])
    notifier = Notifier(config)
    detector = AnomalyDetector(config, monitor, baseline, blocker, notifier)
    unbanner = Unbanner(blocker, notifier, detector)
    dashboard = Dashboard(config, monitor, baseline, blocker)

    # Wire unbanner schedule into blocker
    blocker.unban_schedule = config['unban_schedule']

    # Start all components
    monitor.start()
    baseline.start()
    detector.start()
    unbanner.start()
    dashboard.start()

    print("[Main] All components running.")
    print(f"[Main] Dashboard: http://0.0.0.0:{config['dashboard_port']}")
    print(f"[Main] Watching log: {config['log_path']}")

    # Graceful shutdown on Ctrl+C or SIGTERM
    def shutdown(signum, frame):
        print("\n[Main] Shutting down...")
        monitor.stop()
        baseline.stop()
        detector.stop()
        unbanner.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Keep main thread alive
    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()
