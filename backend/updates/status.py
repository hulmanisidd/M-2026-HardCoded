"""Source freshness tracking and the system status / change summary.

Rule from the brief: missing or stale data is shown as stale/unknown, never
silently treated as safe. A source nobody has heard from is UNKNOWN, not FRESH.
"""
from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from enum import StrEnum

from pydantic import AwareDatetime

from contracts.base import ContractModel

from .models import UpdateResult
from .verification import SourceEvidence


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SourceState(StrEnum):
    FRESH = "fresh"      # last collection succeeded, complete, within max age
    STALE = "stale"      # last good collection is too old, or it was partial
    FAILED = "failed"    # most recent collection attempt failed
    UNKNOWN = "unknown"  # never heard from this source


class OverallState(StrEnum):
    OK = "ok"              # every source fresh and no unresolved drift
    DEGRADED = "degraded"  # something is stale/failed/drifting
    UNKNOWN = "unknown"    # no source has ever reported - cannot say anything


class SourceStatus(ContractModel):
    source: str
    state: SourceState
    last_success_at: AwareDatetime | None = None
    last_failure_at: AwareDatetime | None = None
    last_failure_reason: str | None = None
    age_seconds: float | None = None
    note: str | None = None


class SystemStatus(ContractModel):
    """Change summary for the future API / dashboard."""

    overall: OverallState
    as_of: AwareDatetime
    graph_version: str | None = None
    path_count: int = 0
    sources: tuple[SourceStatus, ...] = ()
    update_counts: dict[str, int] = {}
    verification_counts: dict[str, int] = {}
    last_update_reason: str | None = None
    last_update_at: AwareDatetime | None = None
    last_reconciliation_status: str | None = None
    last_reconciliation_at: AwareDatetime | None = None
    unresolved_drift: int = 0
    notes: tuple[str, ...] = ()


class StatusTracker:
    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = _utc_now,
        max_age: timedelta = timedelta(hours=24),
        max_age_by_source: dict[str, timedelta] | None = None,
        expected_sources: tuple[str, ...] = (),
    ) -> None:
        self._clock = clock
        self._max_age = max_age
        self._max_age_by_source = dict(max_age_by_source or {})
        self._lock = threading.RLock()
        self._success: dict[str, datetime] = {}
        self._failure: dict[str, tuple[datetime, str]] = {}
        self._partial: dict[str, str] = {}
        self._expected = list(expected_sources)
        self._updates: Counter[str] = Counter()
        self._verifications: Counter[str] = Counter()
        self._graph_version: str | None = None
        self._path_count = 0
        self._last_update: tuple[str, datetime] | None = None
        self._last_recon: tuple[str, datetime] | None = None
        self._drift = 0

    # ---- clock / config ---------------------------------------------
    def now(self) -> datetime:
        return self._clock()

    def max_age_for(self, source: str) -> timedelta:
        return self._max_age_by_source.get(source, self._max_age)

    # ---- source freshness -------------------------------------------
    def record_source_success(self, source: str, at: datetime | None = None) -> None:
        at = at or self.now()
        with self._lock:
            prev = self._success.get(source)
            if prev is None or at > prev:
                self._success[source] = at
            self._partial.pop(source, None)
            self._failure.pop(source, None)

    def record_source_partial(
        self, source: str, reason: str, at: datetime | None = None
    ) -> None:
        """Collection returned, but incomplete: usable, never FRESH."""
        at = at or self.now()
        with self._lock:
            prev = self._success.get(source)
            if prev is None or at > prev:
                self._success[source] = at
            self._partial[source] = reason
            self._failure.pop(source, None)

    def record_source_failure(
        self, source: str, reason: str, at: datetime | None = None
    ) -> None:
        with self._lock:
            self._failure[source] = (at or self.now(), reason)

    def source_status(self, source: str, now: datetime | None = None) -> SourceStatus:
        now = now or self.now()
        with self._lock:
            ok = self._success.get(source)
            fail = self._failure.get(source)
            partial = self._partial.get(source)
        age = (now - ok).total_seconds() if ok else None
        fields = dict(
            source=source,
            last_success_at=ok,
            last_failure_at=fail[0] if fail else None,
            last_failure_reason=fail[1] if fail else None,
            age_seconds=age,
        )
        if fail and (ok is None or fail[0] >= ok):
            return SourceStatus(state=SourceState.FAILED, **fields)
        if ok is None:
            return SourceStatus(state=SourceState.UNKNOWN, **fields)
        if partial:
            return SourceStatus(state=SourceState.STALE, note=f"partial: {partial}", **fields)
        if now - ok > self.max_age_for(source):
            return SourceStatus(state=SourceState.STALE, note="older than max age", **fields)
        return SourceStatus(state=SourceState.FRESH, **fields)

    def known_sources(self) -> tuple[str, ...]:
        with self._lock:
            names = set(self._expected) | set(self._success) | set(self._failure)
        return tuple(sorted(names))

    def evidence_for(
        self, sources: tuple[str, ...] | None = None, now: datetime | None = None
    ) -> SourceEvidence:
        """Map source freshness onto the verifier's evidence levels."""
        names = sources or self.known_sources()
        states = [self.source_status(s, now).state for s in names]
        if not states or all(s in (SourceState.UNKNOWN, SourceState.FAILED) for s in states):
            return SourceEvidence.SOURCE_UNAVAILABLE
        if all(s == SourceState.FRESH for s in states):
            return SourceEvidence.SOURCE_CONFIRMED
        return SourceEvidence.SOURCE_STALE

    # ---- activity ----------------------------------------------------
    def record_update(self, result: UpdateResult, path_count: int | None = None) -> None:
        with self._lock:
            key = f"{result.reason}:{result.strategy.value}"
            self._updates[key] += 1
            if result.applied:
                self._graph_version = result.graph_version
                self._last_update = (result.reason, self.now())
            if path_count is not None:
                self._path_count = path_count

    def record_reconciliation(self, status: str, unresolved_drift: int) -> None:
        with self._lock:
            self._last_recon = (status, self.now())
            self._drift = unresolved_drift

    def record_verification(self, status: str) -> None:
        with self._lock:
            self._verifications[status] += 1

    # ---- summary -----------------------------------------------------
    def summary(self) -> SystemStatus:
        now = self.now()
        sources = tuple(self.source_status(s, now) for s in self.known_sources())
        notes: list[str] = []
        with self._lock:
            recon = self._last_recon
            drift = self._drift

        if not sources or all(s.state == SourceState.UNKNOWN for s in sources):
            overall = OverallState.UNKNOWN
            notes.append("no source has reported; nothing can be called safe")
        else:
            bad = [s for s in sources if s.state != SourceState.FRESH]
            for s in bad:
                notes.append(f"source '{s.source}' is {s.state.value}")
            if drift:
                notes.append(f"{drift} unresolved drift item(s)")
            if recon and recon[0] in ("unknown", "drift_detected"):
                notes.append(f"last reconciliation: {recon[0]}")
            degraded = bool(bad) or drift > 0 or (
                recon is not None and recon[0] in ("unknown", "drift_detected")
            )
            overall = OverallState.DEGRADED if degraded else OverallState.OK

        with self._lock:
            return SystemStatus(
                overall=overall,
                as_of=now,
                graph_version=self._graph_version,
                path_count=self._path_count,
                sources=sources,
                update_counts=dict(self._updates),
                verification_counts=dict(self._verifications),
                last_update_reason=self._last_update[0] if self._last_update else None,
                last_update_at=self._last_update[1] if self._last_update else None,
                last_reconciliation_status=recon[0] if recon else None,
                last_reconciliation_at=recon[1] if recon else None,
                unresolved_drift=drift,
                notes=tuple(notes),
            )
