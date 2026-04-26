"""
main.py
-------
Entry point for the HNG Anomaly Detection daemon.

Wires up all components in the correct order:
  1. Load config
  2. Start LogMonitor (tails nginx log → queue)
  3. Start BaselineEngine (rolling statistics)
  4. Start DetectorEngine (sliding windows + anomaly scoring)
  5. Start BlockerEngine (iptables + audit)
  6. Start NotifierEngine (Slack webhooks)
  7. Start UnbannerThread (backoff release)
  8. Start Dashboard Flask app
  9. Main loop: drain queue → baseline.record() → detector.process()

The main loop is intentionally simple and single-threaded for the hot path
(queue drain). All I/O — Slack posts, iptables calls — happen in separate threads.

Run as: python main.py [--config /path/to/config.yaml]
"""

import argparse
import logging
import os
import queue
import signal
import sys
import time

import yaml

from monitor import LogMonitor
from baseline import BaselineEngine
from detector import DetectorEngine
from blocker import BlockerEngine
from unbanner import UnbannerThread
from notifier import NotifierEngine
import dashboard as dash_module

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("main")


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    return cfg


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="HNG Anomaly Detection Daemon")
    parser.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "config.yaml"))
    args = parser.parse_args()

    cfg = load_config(args.config)
    logger.info("Config loaded from %s", args.config)

    audit_path = cfg["log"]["audit_log"]
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)

    # --- Component construction ---
    log_queue: queue.Queue = queue.Queue(maxsize=100_000)

    monitor = LogMonitor(
        log_path=cfg["log"]["nginx_access_log"],
        out_queue=log_queue,
        poll_interval=cfg["log"]["poll_interval_seconds"],
    )

    baseline = BaselineEngine(cfg)
    blocker = BlockerEngine(cfg, audit_path)
    notifier = NotifierEngine(cfg)
    detector = DetectorEngine(cfg, baseline)

    # --- Wire anomaly callbacks ---
    def on_ip_anomaly(ip: str, info: dict):
        """Called by detector when a per-IP anomaly fires."""
        if blocker.is_banned(ip):
            logger.debug("IP %s already banned, skipping", ip)
            return
        condition = (
            f"zscore={info['zscore']:.2f} rate={info['ip_rate']:.2f}req/s "
            f"mean={info['mean']:.2f} tightened={info['tightened']}"
        )
        record = blocker.ban(
            ip=ip,
            condition=condition,
            rate=info["ip_rate"],
            baseline=info["mean"],
        )
        info["condition"] = condition
        notifier.send_ban(ip, info, record)

    def on_global_anomaly(info: dict):
        """Called by detector when global traffic is anomalous."""
        notifier.send_global_anomaly(info)

    detector.on_ip_anomaly = on_ip_anomaly
    detector.on_global_anomaly = on_global_anomaly

    # --- Start background threads ---
    unbanner = UnbannerThread(blocker, notifier)
    unbanner.start()

    monitor.start()

    srv_cfg = cfg["server"]
    dash_module.init(detector, baseline, blocker, audit_path)
    dash_module.run_dashboard(srv_cfg["dashboard_host"], srv_cfg["dashboard_port"])

    # --- Graceful shutdown handler ---
    shutdown = threading.Event() if False else None  # placeholder
    import threading
    shutdown = threading.Event()

    def _sighandler(signum, frame):
        logger.info("Signal %d received, shutting down…", signum)
        shutdown.set()

    signal.signal(signal.SIGINT, _sighandler)
    signal.signal(signal.SIGTERM, _sighandler)

    logger.info("HNG Anomaly Detection daemon is running. Press Ctrl+C to stop.")

    # --- Main processing loop ---
    last_baseline_audit = time.time()

    while not shutdown.is_set():
        try:
            # Drain up to 500 entries per iteration to keep up with bursts
            processed = 0
            while processed < 500:
                try:
                    entry = log_queue.get(timeout=0.05)
                except queue.Empty:
                    break
                baseline.record(entry)
                detector.process(entry)
                processed += 1

            # Write baseline recalc audit entry every minute
            now = time.time()
            if now - last_baseline_audit >= 60:
                mean, stddev = baseline.get_baseline()
                blocker.write_baseline_recalc(mean, stddev)
                last_baseline_audit = now

        except Exception as exc:
            logger.error("Main loop error: %s", exc, exc_info=True)
            time.sleep(1)

    # --- Cleanup ---
    logger.info("Stopping monitor…")
    monitor.stop()
    monitor.join(timeout=5)
    unbanner.stop()
    unbanner.join(timeout=5)
    logger.info("Daemon exited cleanly.")


if __name__ == "__main__":
    main()
