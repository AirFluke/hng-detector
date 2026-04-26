"""
notifier.py
-----------
Sends structured Slack webhook messages for ban, unban, and global anomaly events.

All sends are fire-and-forget via a background thread pool (ThreadPoolExecutor
with 4 workers) so that a slow or failing Slack call never blocks the detector loop.

Message format includes: condition, current rate, baseline, timestamp,
and ban duration where applicable.
"""

import os
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

# Maximum workers for outbound Slack calls
_POOL_SIZE = 4


class NotifierEngine:
    """
    Wraps Slack webhook delivery.

    The webhook URL is read from config; if it contains "${SLACK_WEBHOOK_URL}"
    we expand it from the environment. If the env var is absent, notifications
    are logged as warnings but not sent.
    """

    def __init__(self, cfg: dict):
        raw_url = cfg["slack"]["webhook_url"]
        self._timeout = cfg["slack"]["timeout_seconds"]

        # Expand env var placeholder
        if raw_url.startswith("${") and raw_url.endswith("}"):
            env_key = raw_url[2:-1]
            self._url = os.environ.get(env_key, "")
        else:
            self._url = raw_url

        if not self._url:
            logger.warning(
                "SLACK_WEBHOOK_URL not set. Slack notifications will be logged only."
            )

        self._executor = ThreadPoolExecutor(max_workers=_POOL_SIZE, thread_name_prefix="slack")
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Public send methods                                                  #
    # ------------------------------------------------------------------ #

    def send_ban(self, ip: str, info: dict, record):
        """Send a ban notification. `record` is a BanRecord from blocker.py."""
        ts = _fmt_ts(info["timestamp"])
        text = (
            f":rotating_light: *IP BANNED* — `{ip}`\n"
            f"*Condition:* {info.get('condition', 'anomaly')}\n"
            f"*Rate:* `{info['ip_rate']:.2f} req/s`  "
            f"*Baseline mean:* `{info['mean']:.2f}`  "
            f"*Z-score:* `{info['zscore']:.2f}`\n"
            f"*Duration:* `{record.duration_label}`  "
            f"*Ban #{record.ban_count}*\n"
            f"*Time:* {ts}"
        )
        self._send_async(text)

    def send_unban(self, record):
        """Send an unban notification."""
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        text = (
            f":white_check_mark: *IP UNBANNED* — `{record.ip}`\n"
            f"*Was banned for:* `{record.duration_label}` (ban #{record.ban_count})\n"
            f"*Original condition:* {record.condition}\n"
            f"*Original rate:* `{record.rate:.2f} req/s`  "
            f"*Baseline:* `{record.baseline:.2f}`\n"
            f"*Time:* {ts}"
        )
        self._send_async(text)

    def send_global_anomaly(self, info: dict):
        """Send a global traffic spike notification (no IP ban)."""
        ts = _fmt_ts(info["timestamp"])
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Global rate:* `{info['global_rate']:.2f} req/s`  "
            f"*Baseline mean:* `{info['mean']:.2f}`  "
            f"*Z-score:* `{info['zscore']:.2f}`\n"
            f"*Action:* Slack alert only (no single IP to block)\n"
            f"*Time:* {ts}"
        )
        self._send_async(text)

    # ------------------------------------------------------------------ #
    # Internals                                                            #
    # ------------------------------------------------------------------ #

    def _send_async(self, text: str):
        """Submit the Slack POST to the executor without blocking the caller."""
        if not self._url:
            logger.warning("[SLACK-SKIP] %s", text[:120])
            return
        self._executor.submit(self._post, text)

    def _post(self, text: str):
        """Blocking POST to Slack webhook. Runs in executor thread."""
        payload = {"text": text}
        try:
            resp = requests.post(
                self._url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                logger.warning("Slack returned %d: %s", resp.status_code, resp.text[:200])
        except requests.RequestException as exc:
            logger.error("Slack POST failed: %s", exc)


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
