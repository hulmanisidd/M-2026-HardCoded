"""The only door into the graph. In-memory and Neo4j both implement this."""
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import datetime

from contracts import Entity, GraphSnapshot, Relationship

from .models import GraphChange, Scope


class GraphRepository(ABC):
    @abstractmethod
    def upsert_entity(
        self, entity: Entity, *, observed_at: datetime | None = None
    ) -> GraphChange:
        """Insert or replace by entity_id. Identical replay -> changed=False."""

    @abstractmethod
    def upsert_edge(
        self,
        edge: Relationship,
        *,
        reinstate: bool = False,
        observed_at: datetime | None = None,
        source_api: str | None = None,
    ) -> GraphChange:
        """Insert or replace by edge_id. Both endpoints must already exist
        (raise ValueError otherwise). Identical replay -> changed=False.

        observed_at is the event time of this observation (P1's occurred_at).
        When given for an edge we already hold, the write is ignored
        (changed=False) unless observed_at is strictly newer than the edge's
        latest observation, invalidation or unknown-marking. This makes
        out-of-order and replayed delivery harmless. Once the contract has
        Relationship.observed_at the updater copies it here.

        An INVALIDATED edge is never overwritten by a non-invalidated edge
        unless reinstate=True or observed_at is newer than its invalidation
        time (a fresh re-grant). Otherwise the write is ignored.

        source_api records which collector reported the edge, so a failed
        collection can mark its scope UNKNOWN. Omitted -> keep what we have.
        A fresh observation of an UNKNOWN edge clears the UNKNOWN. A write
        without observed_at to an UNKNOWN edge is ignored (changed=False)
        unless the write is itself UNKNOWN or INVALIDATED."""

    @abstractmethod
    def invalidate_edge(self, edge_id: str, *, at: datetime | None = None) -> GraphChange:
        """Mark INVALIDATED (kept for history, never deleted).
        Unknown edge_id -> KeyError. Already invalidated -> changed=False.

        at is the event time of the removal. If given and not strictly newer
        than the edge's latest observation, the removal is stale and ignored
        (changed=False). Omitted -> unconditional, stamped with the clock."""

    @abstractmethod
    def mark_scope_unknown(self, scope: Scope, *, at: datetime) -> GraphChange:
        """A collection for `scope` failed or was partial. Every held edge that
        was reported by scope.source_api and whose source entity is in
        scope.account_id becomes UNKNOWN, except INVALIDATED edges. Edges whose
        latest event is not older than `at` are skipped (the failure report is
        stale for them). Edges with no observed_at (seed / direct writes)
        are never marked UNKNOWN. UNKNOWN is cleared only by a newer
        observation."""

    @abstractmethod
    def get_entity(self, entity_id: str) -> Entity | None: ...

    @abstractmethod
    def get_edge(self, edge_id: str) -> Relationship | None:
        """Stored edge. Staleness is applied only in snapshot(); P3/P4 must
        read snapshots, not this."""

    @abstractmethod
    def get_neighbors(self, entity_id: str) -> list[Relationship]:
        """Outgoing stored edges, sorted by edge_id."""

    @abstractmethod
    def snapshot(self) -> GraphSnapshot:
        """Immutable, versioned view. Same content -> same version string.
        Confirmed/inferred edges older than the freshness window at
        created_at are returned as STALE."""

    @abstractmethod
    def subscribe(self, callback: Callable[[GraphChange], None]) -> None:
        """Call callback(change) after every write that changed the graph
        (changed=True). Replays and ignored writes do not notify."""