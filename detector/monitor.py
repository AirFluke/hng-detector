"""
monitor.py
----------
Continuously tails the Nginx JSON access log and emits parsed log entries
as Python dicts into a shared queue consumed by the detector.

Key design:
- Uses a blocking tail (seek to end, then readline in a loop with a short sleep)
- Handles log rotation by reopening the file when inode changes
- Drops malformed lines with a warning; never crashes the daemon
"""

import json
import os
import time
import queue
import logging
import threading

logger = logging.getLogger(__name__)


def _get_inode(path: str) -> int:
    """Return the inode of a file, or -1 if the file doesn't exist."""
    try:
        return os.stat(path).st_ino
    except FileNotFoundError:
        return -1


def parse_line(raw: str) -> dict | None:
    """
    Parse a single JSON log line emitted by Nginx.

    Expected fields (from nginx.conf log_format):
      source_ip, timestamp, method, path, status, response_size

    Returns None if the line is malformed or missing required fields.
    """
    raw = raw.strip()
    if not raw:
        return None
    try:
        entry = json.loads(raw)
    except json.JSONDecodeError:
        logger.debug("Dropping non-JSON line: %s", raw[:120])
        return None

    required = {"source_ip", "timestamp", "method", "path", "status", "response_size"}
    missing = required - entry.keys()
    if missing:
        logger.debug("Dropping line missing fields %s: %s", missing, raw[:120])
        return None

    # Coerce types
    try:
        entry["status"] = int(entry["status"])
        entry["response_size"] = int(entry["response_size"])
        entry["_parsed_at"] = time.time()   # monotonic wall time for window math
    except (ValueError, TypeError) as exc:
        logger.debug("Type coercion failed (%s): %s", exc, raw[:120])
        return None

    return entry


class LogMonitor(threading.Thread):
    """
    Background thread that tails the Nginx access log and puts parsed entries
    onto `out_queue`.

    Handles:
    - File not yet existing (waits and retries)
    - Log rotation (detects inode change, reopens)
    - Seek to end on first open (avoids replaying historical traffic)
    """

    def __init__(self, log_path: str, out_queue: queue.Queue, poll_interval: float = 0.1):
        super().__init__(name="LogMonitor", daemon=True)
        self.log_path = log_path
        self.out_queue = out_queue
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("LogMonitor starting — watching %s", self.log_path)
        fh = None
        current_inode = -1
        first_open = True

        while not self._stop_event.is_set():
            # --- File existence check ---
            if not os.path.exists(self.log_path):
                if fh:
                    fh.close()
                    fh = None
                logger.warning("Log file not found, waiting: %s", self.log_path)
                time.sleep(2)
                continue

            # --- Inode / rotation check ---
            new_inode = _get_inode(self.log_path)
            if new_inode != current_inode:
                if fh:
                    # Drain remaining bytes from the old file before switching
                    for raw in fh:
                        entry = parse_line(raw)
                        if entry:
                            self.out_queue.put(entry)
                    fh.close()
                    logger.info("Log rotated (inode %d → %d), reopening", current_inode, new_inode)
                fh = open(self.log_path, "r", encoding="utf-8", errors="replace")
                if first_open:
                    fh.seek(0, 2)   # seek to end; don't replay old traffic
                    first_open = False
                    logger.info("Seeked to end of existing log")
                current_inode = new_inode

            # --- Read available lines ---
            line = fh.readline()
            if line:
                entry = parse_line(line)
                if entry:
                    self.out_queue.put(entry)
            else:
                # No new data; yield CPU
                time.sleep(self.poll_interval)

        if fh:
            fh.close()
        logger.info("LogMonitor stopped")
