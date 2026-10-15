"""Stale-result protection.

Graph versions are content hashes, so two versions cannot be ordered by
comparing them. Instead every computation takes a monotonically increasing
*epoch* when it starts. A result may only be committed if no computation that
started later has already committed - an older result can never overwrite a
newer one, even if it finishes last.
"""
from __future__ import annotations

import threading


class EpochGuard:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._issued = 0
        self._committed = 0
        self._in_flight = 0

    def begin(self) -> tuple[int, bool]:
        """Start a computation. Returns (epoch, other_computations_in_flight)."""
        with self._lock:
            self._issued += 1
            self._in_flight += 1
            return self._issued, self._in_flight > 1

    def commit(self, epoch: int) -> bool:
        """Finish a computation. True only if its result is still the newest."""
        with self._lock:
            self._in_flight -= 1
            if epoch <= self._committed:
                return False
            self._committed = epoch
            return True

    def abort(self, epoch: int) -> None:
        """Finish a computation that produced no result (error / nothing to do)."""
        with self._lock:
            self._in_flight -= 1

    @property
    def committed_epoch(self) -> int:
        with self._lock:
            return self._committed
