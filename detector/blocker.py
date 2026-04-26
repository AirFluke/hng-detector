"""
blocker.py
----------
Manages per-IP iptables DROP rules.

Each ban is recorded in an in-memory dict keyed by IP. The dict stores how
many times this IP has been banned (determines which backoff slot to use) and
when the ban expires. The unbanner thread calls `get_expired_bans()` periodically.

Audit log format (append-only):
  [ISO8601] ACTION ip=<ip> | condition=<str> | rate=<float> | baseline=<float> | duration=<Nm|permanent>
"""

import subprocess
import threading
import logging
import os
from datetime import datetime, timedelta
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BanRecord:
    ip: str
    ban_count: int          # 1-based; determines which schedule slot applies
    banned_at: datetime
    expires_at: datetime | None    # None = permanent
    condition: str
    rate: float
    baseline: float

    @property
    def duration_label(self) -> str:
        if self.expires_at is None:
            return "permanent"
        minutes = int((self.expires_at - self.banned_at).total_seconds() / 60)
        if minutes >= 60:
            return f"{minutes // 60}h"
        return f"{minutes}m"


class BlockerEngine:
    """
    Issues iptables DROP rules and maintains ban state.

    Thread-safe: all public methods acquire self._lock.
    """

    def __init__(self, cfg: dict, audit_log_path: str):
        schedule = cfg["blocking"]["ban_schedule_minutes"]   # e.g. [10, 30, 120, -1]
        self._schedule: list[int] = schedule                 # -1 = permanent
        self._audit_path = audit_log_path
        self._lock = threading.Lock()
        self._bans: dict[str, BanRecord] = {}                # ip -> BanRecord

        os.makedirs(os.path.dirname(audit_log_path), exist_ok=True)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def ban(self, ip: str, condition: str, rate: float, baseline: float) -> BanRecord:
        """
        Add an iptables DROP rule for `ip` and record the ban.
        Returns the BanRecord (also notified to Slack by the caller).
        """
        with self._lock:
            existing = self._bans.get(ip)
            ban_count = (existing.ban_count + 1) if existing else 1

            # Pick duration from schedule (clamp to last slot for repeat offenders)
            slot_idx = min(ban_count - 1, len(self._schedule) - 1)
            duration_min = self._schedule[slot_idx]

            now = datetime.utcnow()
            if duration_min == -1:
                expires_at = None   # permanent
            else:
                expires_at = now + timedelta(minutes=duration_min)

            record = BanRecord(
                ip=ip,
                ban_count=ban_count,
                banned_at=now,
                expires_at=expires_at,
                condition=condition,
                rate=rate,
                baseline=baseline,
            )
            self._bans[ip] = record

        # Issue iptables rule
        self._iptables_add(ip)

        # Write audit entry
        self._audit("BAN", record)

        logger.info("[BAN] ip=%s ban_count=%d duration=%s", ip, ban_count, record.duration_label)
        return record

    def unban(self, ip: str) -> BanRecord | None:
        """Remove the iptables rule for `ip` and return the old BanRecord."""
        with self._lock:
            record = self._bans.pop(ip, None)

        if not record:
            return None

        self._iptables_remove(ip)
        self._audit("UNBAN", record)
        logger.info("[UNBAN] ip=%s", ip)
        return record

    def get_expired_bans(self) -> list[str]:
        """Return list of IPs whose ban has expired (not including permanent bans)."""
        now = datetime.utcnow()
        with self._lock:
            return [
                ip for ip, rec in self._bans.items()
                if rec.expires_at is not None and now >= rec.expires_at
            ]

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._bans

    def get_banned_ips(self) -> list[BanRecord]:
        with self._lock:
            return list(self._bans.values())

    def write_baseline_recalc(self, mean: float, stddev: float):
        """Write a BASELINE_RECALC audit entry (called by the baseline engine callback)."""
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        line = (
            f"[{ts}] BASELINE_RECALC ip=N/A | condition=recalculation "
            f"| rate={mean:.3f} | baseline={stddev:.3f} | duration=N/A\n"
        )
        self._append_audit(line)

    # ------------------------------------------------------------------ #
    # iptables helpers                                                     #
    # ------------------------------------------------------------------ #

    def _iptables_add(self, ip: str):
        """Add INPUT DROP rule for `ip`. Idempotent — checks before inserting."""
        try:
            # Check if rule already exists
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            if check.returncode == 0:
                logger.debug("iptables rule already exists for %s", ip)
                return
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            logger.info("iptables: added DROP for %s", ip)
        except subprocess.CalledProcessError as exc:
            logger.error("iptables add failed for %s: %s", ip, exc.stderr)
        except FileNotFoundError:
            logger.warning("iptables not found — running in dev mode, skipping block for %s", ip)

    def _iptables_remove(self, ip: str):
        """Remove INPUT DROP rule for `ip`. Safe to call even if rule doesn't exist."""
        try:
            while True:
                result = subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True
                )
                if result.returncode != 0:
                    break   # no more rules for this IP
            logger.info("iptables: removed DROP for %s", ip)
        except FileNotFoundError:
            logger.warning("iptables not found — dev mode, skip unblock %s", ip)

    # ------------------------------------------------------------------ #
    # Audit log                                                            #
    # ------------------------------------------------------------------ #

    def _audit(self, action: str, record: BanRecord):
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        line = (
            f"[{ts}] {action} ip={record.ip} "
            f"| condition={record.condition} "
            f"| rate={record.rate:.3f} "
            f"| baseline={record.baseline:.3f} "
            f"| duration={record.duration_label}\n"
        )
        self._append_audit(line)

    def _append_audit(self, line: str):
        try:
            with open(self._audit_path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            logger.error("Failed to write audit log: %s", exc)
