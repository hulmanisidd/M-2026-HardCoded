"""Bridges into P5 from P1 (normalized events) and P2 (graph writes).

* EventIntake        - takes a P1 NormalizedEvent, de-duplicates it, asks P2 to
                       apply it (through an injected applier) and forwards the
                       resulting GraphChanges to the coordinator.
* NotifyingGraphRepository - wraps any GraphRepository and forwards every
                       write's GraphChange to listeners, so P5 "subscribes" to
                       P2 without P2 changing.
* EdgeInvalidationApplier  - reference applier used until P2 exposes
                       `apply_event`. Handles one event type only.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable

from backend.graph.models import GraphChange
from backend.graph.repository import GraphRepository
from contracts import Entity, GraphSnapshot, NormalizedEvent, Relationship
from contracts.base import ContractModel

from .coordinator import UpdateCoordinator
from .models import UpdateResult
from .status import StatusTracker

# P2's future `apply_event(event) -> GraphChange` (one or many changes).
EventApplier = Callable[[NormalizedEvent], Iterable[GraphChange]]
ChangeListener = Callable[[GraphChange], object]


class EventOutcome(ContractModel):
    event_id: str
    accepted: bool
    reason: str   # applied | no_graph_change | duplicate_event | no_event_applier | apply_failed
    updates: tuple[UpdateResult, ...] = ()
    error: str | None = None


class EventIntake:
    def __init__(
        self,
        coordinator: UpdateCoordinator,
        applier: EventApplier | None,
        *,
        status: StatusTracker | None = None,
        max_remembered: int = 10_000,
    ) -> None:
        self._coordinator = coordinator
        self._applier = applier
        self._status = status
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._max = max_remembered
        self._lock = threading.Lock()

    def _remember(self, event_id: str) -> bool:
        """True if newly remembered, False if already seen."""
        with self._lock:
            if event_id in self._seen:
                return False
            self._seen[event_id] = None
            while len(self._seen) > self._max:
                self._seen.popitem(last=False)
            return True

    def _forget(self, event_id: str) -> None:
        with self._lock:
            self._seen.pop(event_id, None)

    def handle_event(self, event: NormalizedEvent) -> EventOutcome:
        if self._applier is None:
            return EventOutcome(event_id=event.event_id, accepted=False, reason="no_event_applier")
        if not self._remember(event.event_id):
            return EventOutcome(event_id=event.event_id, accepted=False, reason="duplicate_event")

        try:
            changes = tuple(self._applier(event))
        except Exception as exc:
            self._forget(event.event_id)  # not applied: a retry must be allowed
            reason = f"{type(exc).__name__}: {exc}"
            if self._status:
                self._status.record_source_failure(event.source, reason)
            return EventOutcome(
                event_id=event.event_id, accepted=False, reason="apply_failed", error=reason
            )

        if self._status:
            self._status.record_source_success(event.source, at=event.ingested_at or event.occurred_at)
        updates = tuple(self._coordinator.handle_change(c) for c in changes)
        reason = "applied" if any(c.changed for c in changes) else "no_graph_change"
        return EventOutcome(event_id=event.event_id, accepted=True, reason=reason, updates=updates)


class NotifyingGraphRepository(GraphRepository):
    """Decorator: every write returns its GraphChange AND notifies listeners."""

    def __init__(self, inner: GraphRepository, *listeners: ChangeListener) -> None:
        self._inner = inner
        self._listeners = list(listeners)

    def subscribe(self, listener: ChangeListener) -> None:
        self._listeners.append(listener)

    def _notify(self, change: GraphChange) -> GraphChange:
        for listener in self._listeners:
            listener(change)
        return change

    def upsert_entity(self, entity: Entity) -> GraphChange:
        return self._notify(self._inner.upsert_entity(entity))

    def upsert_edge(self, edge: Relationship, *, reinstate: bool = False) -> GraphChange:
        return self._notify(self._inner.upsert_edge(edge, reinstate=reinstate))

    def invalidate_edge(self, edge_id: str) -> GraphChange:
        return self._notify(self._inner.invalidate_edge(edge_id))

    def get_entity(self, entity_id: str) -> Entity | None:
        return self._inner.get_entity(entity_id)

    def get_edge(self, edge_id: str) -> Relationship | None:
        return self._inner.get_edge(edge_id)

    def get_neighbors(self, entity_id: str) -> list[Relationship]:
        return self._inner.get_neighbors(entity_id)

    def snapshot(self) -> GraphSnapshot:
        return self._inner.snapshot()


class EdgeInvalidationApplier:
    """Reference applier: event_type "iam.edge.invalidated", attributes["edge_id"]."""

    EVENT_TYPE = "iam.edge.invalidated"

    def __init__(self, repo: GraphRepository) -> None:
        self._repo = repo

    def __call__(self, event: NormalizedEvent) -> list[GraphChange]:
        if event.event_type != self.EVENT_TYPE:
            return []
        return [self._repo.invalidate_edge(event.attributes["edge_id"])]
