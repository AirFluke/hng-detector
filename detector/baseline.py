"""
baseline.py
-----------
Maintains a rolling 30-minute baseline of per-second request counts.

Algorithm:
  - Every second we record how many requests arrived in that second into
    `_second_buckets` (a deque capped at 30*60 = 1800 entries).
  - Every `recalc_interval` seconds we recompute mean and stddev from
    whatever is currently in the deque.
  - We also track per-hour slots (0-23). When the current hour has ≥
    `min_samples` buckets we prefer its statistics.
  - Floor values prevent division-by-zero and stop absurdly low baselines
    from triggering false positives during quiet nights.

Thread safety:
  - A single threading.Lock guards all mutable state.
  - The detector reads `get_baseline()` from its own thread; that read
    is a tuple copy, safe without acquiring the lock.
"""

import math
import time
import threading
import logging
from collections import deque
from datetime import datetime

logger = logging.getLogger(__name__)


class BaselineEngine:
    """
    Tracks per-second request counts and derives a rolling statistical baseline.

    Attributes exposed (read-only, set atomically):
      effective_mean   float  — baseline mean req/s
      effective_stddev float  — baseline stddev
      last_recalc_at   float  — wall time of last recalculation
      history          list   — list of (timestamp, mean, stddev) for the audit graph
    """

    def __init__(self, cfg: dict):
        bl = cfg["baseline"]
        det = cfg.get("detection", {})

        self._window_seconds = bl["rolling_window_minutes"] * 60  # 1800
        self._recalc_interval = bl["recalculation_interval_seconds"]
        self._min_samples = bl["min_samples_for_baseline"]
        self._floor_mean = bl["floor_mean"]
        self._floor_stddev = bl["floor_stddev"]
        self._prefer_current_hour = bl.get("prefer_current_hour", True)

        self._lock = threading.Lock()

        # Rolling bucket of per-second request counts
        # Each element: float count (requests in that one-second slot)
        self._second_buckets: deque[float] = deque(maxlen=self._window_seconds)

        # Per-hour slot accumulation: hour -> list of per-second counts
        self._hour_slots: dict[int, deque[float]] = {
            h: deque(maxlen=self._window_seconds) for h in range(24)
        }

        # Current-second accumulator
        self._current_second: int = int(time.time())
        self._current_count: float = 0.0

        # Published baseline (written under lock, read without lock)
        self.effective_mean: float = self._floor_mean
        self.effective_stddev: float = self._floor_stddev
        self.last_recalc_at: float = time.time()

        # Audit history: list of (iso_timestamp, mean, stddev)
        self.history: list[tuple[str, float, float]] = []

        self._next_recalc: float = time.time() + self._recalc_interval

        # Per-second error tracking (4xx/5xx)
        self._error_second_buckets: deque[float] = deque(maxlen=self._window_seconds)
        self._current_error_count: float = 0.0
        self.effective_error_mean: float = 0.0
        self.effective_error_stddev: float = 0.0

    def record(self, entry: dict):
        """
        Called for every parsed log entry. Accumulates into the current second's bucket.
        Flushes the bucket when the clock second changes and triggers recalculation if due.
        """
        now = entry["_parsed_at"]
        bucket_sec = int(now)
        status = entry.get("status", 200)
        is_error = status >= 400

        with self._lock:
            # Flush completed seconds
            if bucket_sec > self._current_second:
                for s in range(self._current_second, bucket_sec):
                    self._second_buckets.append(self._current_count)
                    self._error_second_buckets.append(self._current_error_count)
                    hour = datetime.fromtimestamp(float(s)).hour
                    self._hour_slots[hour].append(self._current_count)
                    self._current_count = 0.0
                    self._current_error_count = 0.0
                self._current_second = bucket_sec

            self._current_count += 1.0
            if is_error:
                self._current_error_count += 1.0

            # Trigger recalculation if interval elapsed
            if now >= self._next_recalc:
                self._recalculate()
                self._next_recalc = now + self._recalc_interval

    def _recalculate(self):
        """
        Recompute effective_mean and effective_stddev from the rolling window.
        Prefers the current hour's slot when it has enough data.
        Must be called with self._lock held.
        """
        current_hour = datetime.now().hour
        hour_slot = self._hour_slots[current_hour]

        if self._prefer_current_hour and len(hour_slot) >= self._min_samples:
            samples = list(hour_slot)
            source = f"hour-{current_hour:02d}"
        elif len(self._second_buckets) >= self._min_samples:
            samples = list(self._second_buckets)
            source = "rolling-30m"
        else:
            logger.debug("Not enough samples for baseline yet (%d < %d)",
                         len(self._second_buckets), self._min_samples)
            return

        n = len(samples)
        mean = sum(samples) / n
        variance = sum((x - mean) ** 2 for x in samples) / max(n - 1, 1)
        stddev = math.sqrt(variance)

        # Apply floors
        mean = max(mean, self._floor_mean)
        stddev = max(stddev, self._floor_stddev)

        self.effective_mean = mean
        self.effective_stddev = stddev
        self.last_recalc_at = time.time()

        # Error baseline
        err_samples = list(self._error_second_buckets)
        if err_samples:
            err_mean = sum(err_samples) / len(err_samples)
            err_var = sum((x - err_mean) ** 2 for x in err_samples) / max(len(err_samples) - 1, 1)
            self.effective_error_mean = max(err_mean, 0.1)
            self.effective_error_stddev = max(math.sqrt(err_var), 0.1)

        ts = datetime.now().isoformat(timespec="seconds")
        self.history.append((ts, mean, stddev))
        # Keep only last 200 history points
        if len(self.history) > 200:
            self.history = self.history[-200:]

        logger.info(
            "[BASELINE RECALC] source=%s samples=%d mean=%.3f stddev=%.3f",
            source, n, mean, stddev
        )

    def get_baseline(self) -> tuple[float, float]:
        """Return (effective_mean, effective_stddev) — safe to call without lock."""
        return self.effective_mean, self.effective_stddev

    def get_error_baseline(self) -> tuple[float, float]:
        """Return (effective_error_mean, effective_error_stddev)."""
        return self.effective_error_mean, self.effective_error_stddev
