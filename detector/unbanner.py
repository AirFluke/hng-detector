"""
unbanner.py
-----------
Background thread that periodically checks for expired bans and releases them,
firing a Slack notification on each unban.

Runs every 30 seconds; fine-grained enough to honour the 10-minute minimum
ban without burning CPU.
"""

import time
import threading
import logging

logger = logging.getLogger(__name__)

CHECK_INTERVAL = 30   # seconds between sweeps


class UnbannerThread(threading.Thread):
    """
    Polls the blocker for expired bans, calls blocker.unban(), then notifies
    via the notifier.

    Arguments:
        blocker  — BlockerEngine instance
        notifier — NotifierEngine instance
    """

    def __init__(self, blocker, notifier):
        super().__init__(name="Unbanner", daemon=True)
        self._blocker = blocker
        self._notifier = notifier
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        logger.info("Unbanner started (check interval %ds)", CHECK_INTERVAL)
        while not self._stop.wait(CHECK_INTERVAL):
            try:
                expired = self._blocker.get_expired_bans()
                for ip in expired:
                    record = self._blocker.unban(ip)
                    if record:
                        self._notifier.send_unban(record)
            except Exception as exc:
                logger.error("Unbanner error: %s", exc, exc_info=True)
        logger.info("Unbanner stopped")
