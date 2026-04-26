"""
detector.py
-----------
Maintains two deque-based sliding windows (one per-IP, one global) over the
last 60 seconds and scores each new request against the current baseline.

Sliding Window Design
---------------------
Each window is a collections.deque of (timestamp: float) values.
On every new event we:
  1. Append the event's timestamp.
  2. Evict all entries whose age > window_seconds from the LEFT end.
     (Deques are O(1) for both append and popleft.)
  3. Rate = len(deque) / window_seconds

This gives us a true sliding-window count without any per-minute bucketing.

Anomaly Conditions (either fires the alert):
  - Z-score: (rate - mean) / stddev > zscore_threshold
  - Multiplier: rate > multiplier_threshold × mean

Error Surge Tightening:
  If an IP's recent 4xx/5xx rate exceeds error_surge_multiplier × error_mean,
  we use tightened_zscore and tightened_multiplier thresholds for that IP only.
"""

import time
import threading
import logging
from collections import deque, defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class IPState:
    """All per-IP sliding window state."""
    timestamps: deque = field(default_factory=deque)    # request timestamps
    error_ts: deque = field(default_factory=deque)       # 4xx/5xx timestamps
    ban_count: int = 0                                   # number of times banned
    tightened: bool = False                              # error surge flag


class DetectorEngine:
    """
    Evaluates each parsed log entry against the baseline and fires anomaly
    callbacks when thresholds are exceeded.

    Usage:
        detector = DetectorEngine(cfg, baseline_engine)
        detector.on_ip_anomaly = lambda ip, info: ...
        detector.on_global_anomaly = lambda info: ...
        detector.process(entry)   # called for every log line
    """

    def __init__(self, cfg: dict, baseline):
        det = cfg["detection"]
        sw = cfg["sliding_window"]

        self._ip_window = sw["ip_window_seconds"]          # 60 s
        self._global_window = sw["global_window_seconds"]  # 60 s
        self._zscore_thresh = det["zscore_threshold"]      # 3.0
        self._mult_thresh = det["multiplier_threshold"]    # 5.0
        self._error_mult = det["error_surge_multiplier"]   # 3.0
        self._tight_z = det["tightened_zscore"]            # 2.0
        self._tight_m = det["tightened_multiplier"]        # 3.0

        self._baseline = baseline

        # Per-IP state (created on first sight of each IP)
        self._ip_states: dict[str, IPState] = defaultdict(IPState)

        # Global sliding window
        self._global_ts: deque[float] = deque()

        # Cooldown: don't re-fire the same IP alert within 10 seconds
        self._last_fired: dict[str, float] = {}
        self._global_last_fired: float = 0.0

        self._lock = threading.Lock()

        # Callbacks — set these before calling process()
        self.on_ip_anomaly = None       # fn(ip: str, info: dict) -> None
        self.on_global_anomaly = None   # fn(info: dict) -> None

        # Expose current state for the dashboard
        self.global_rate: float = 0.0
        self.top_ips: list[tuple[str, float]] = []  # [(ip, rate), ...]
        self._last_top_update: float = 0.0

    def _evict(self, dq: deque, window: float, now: float):
        """
        Remove all timestamps from the LEFT of `dq` that are older than `window` seconds.
        Deque popleft is O(1).
        """
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _rate(self, dq: deque, window: float) -> float:
        """Requests per second over the window."""
        return len(dq) / window

    def _zscore(self, rate: float, mean: float, stddev: float) -> float:
        if stddev == 0:
            return 0.0
        return (rate - mean) / stddev

    def process(self, entry: dict):
        """
        Main entry point. Called for every parsed log line from the queue.
        Updates windows, checks thresholds, fires callbacks.
        """
        ip = entry["source_ip"]
        now = entry["_parsed_at"]
        status = entry.get("status", 200)
        is_error = status >= 400

        mean, stddev = self._baseline.get_baseline()
        err_mean, err_stddev = self._baseline.get_error_baseline()

        with self._lock:
            state = self._ip_states[ip]

            # --- Update per-IP windows ---
            state.timestamps.append(now)
            self._evict(state.timestamps, self._ip_window, now)
            if is_error:
                state.error_ts.append(now)
            self._evict(state.error_ts, self._ip_window, now)

            # --- Update global window ---
            self._global_ts.append(now)
            self._evict(self._global_ts, self._global_window, now)

            ip_rate = self._rate(state.timestamps, self._ip_window)
            err_rate = self._rate(state.error_ts, self._ip_window)
            global_rate = self._rate(self._global_ts, self._global_window)
            self.global_rate = global_rate

            # --- Error surge check (tightens thresholds for this IP) ---
            if err_mean > 0 and err_rate >= self._error_mult * err_mean:
                if not state.tightened:
                    state.tightened = True
                    logger.info("[ERROR SURGE] ip=%s err_rate=%.2f err_mean=%.2f — thresholds tightened",
                                ip, err_rate, err_mean)
            else:
                state.tightened = False

            # --- Choose thresholds ---
            z_thresh = self._tight_z if state.tightened else self._zscore_thresh
            m_thresh = self._tight_m if state.tightened else self._mult_thresh

            # --- Per-IP anomaly detection ---
            ip_z = self._zscore(ip_rate, mean, stddev)
            ip_anomaly = (ip_z > z_thresh) or (ip_rate > m_thresh * mean and mean > 0)

            if ip_anomaly:
                cooldown_ok = (now - self._last_fired.get(ip, 0)) > 10
                if cooldown_ok and self.on_ip_anomaly:
                    self._last_fired[ip] = now
                    info = {
                        "ip": ip,
                        "ip_rate": round(ip_rate, 3),
                        "global_rate": round(global_rate, 3),
                        "mean": round(mean, 3),
                        "stddev": round(stddev, 3),
                        "zscore": round(ip_z, 3),
                        "tightened": state.tightened,
                        "timestamp": now,
                    }
                    # Fire callback outside lock to avoid deadlock
                    self._lock.release()
                    try:
                        self.on_ip_anomaly(ip, info)
                    finally:
                        self._lock.acquire()

            # --- Global anomaly detection ---
            g_z = self._zscore(global_rate, mean, stddev)
            global_anomaly = (g_z > self._zscore_thresh) or \
                             (global_rate > self._mult_thresh * mean and mean > 0)

            if global_anomaly:
                global_cooldown_ok = (now - self._global_last_fired) > 30
                if global_cooldown_ok and self.on_global_anomaly:
                    self._global_last_fired = now
                    info = {
                        "global_rate": round(global_rate, 3),
                        "mean": round(mean, 3),
                        "stddev": round(stddev, 3),
                        "zscore": round(g_z, 3),
                        "timestamp": now,
                    }
                    self._lock.release()
                    try:
                        self.on_global_anomaly(info)
                    finally:
                        self._lock.acquire()

            # --- Update top IPs every 5 seconds ---
            if now - self._last_top_update > 5:
                rates = [
                    (i, self._rate(s.timestamps, self._ip_window))
                    for i, s in self._ip_states.items()
                ]
                self.top_ips = sorted(rates, key=lambda x: x[1], reverse=True)[:10]
                self._last_top_update = now

    def get_snapshot(self) -> dict:
        """Return a thread-safe snapshot for the dashboard."""
        with self._lock:
            return {
                "global_rate": round(self.global_rate, 3),
                "top_ips": list(self.top_ips),
            }
