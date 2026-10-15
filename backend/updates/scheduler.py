"""Periodic reconciliation.

`tick(now)` is deterministic and clock-injectable so tests never sleep.
`start_background` wraps it in a daemon thread for real use.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from .reconciliation import ReconciliationResult


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ReconciliationScheduler:
    def __init__(
        self,
        reconcile: Callable[[], ReconciliationResult],
        interval: timedelta,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if interval <= timedelta(0):
            raise ValueError("interval must be positive")
        self._reconcile = reconcile
        self._interval = interval
        self._clock = clock
        self._last_run: datetime | None = None
        self.last_result: ReconciliationResult | None = None
        self.last_error: str | None = None
        self.runs = 0

    def due(self, now: datetime | None = None) -> bool:
        now = now or self._clock()
        return self._last_run is None or now - self._last_run >= self._interval

    def tick(self, now: datetime | None = None) -> ReconciliationResult | None:
        """Run a reconciliation if one is due. Never raises.

        A failed run is remembered in `last_error` and retried after the normal
        interval (no hot retry loop).
        """
        now = now or self._clock()
        if not self.due(now):
            return None
        self._last_run = now
        self.runs += 1
        try:
            self.last_result = self._reconcile()
            self.last_error = None
            return self.last_result
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return None

    def start_background(
        self, poll_seconds: float = 1.0
    ) -> tuple[threading.Thread, threading.Event]:
        stop = threading.Event()

        def loop() -> None:
            while not stop.is_set():
                self.tick()
                stop.wait(poll_seconds)

        thread = threading.Thread(target=loop, name="p5-reconciler", daemon=True)
        thread.start()
        return thread, stop
