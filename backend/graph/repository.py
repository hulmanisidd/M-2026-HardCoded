"""The only door into the graph. In-memory and Neo4j both implement this."""
from abc import ABC, abstractmethod

from contracts import Entity, GraphSnapshot, Relationship

from .models import GraphChange


class GraphRepository(ABC):
    @abstractmethod
    def upsert_entity(self, entity: Entity) -> GraphChange:
        """Insert or replace by entity_id. Identical replay -> changed=False."""

    @abstractmethod
    def upsert_edge(self, edge: Relationship) -> GraphChange:
        """Insert or replace by edge_id. Both endpoints must already exist
        (raise ValueError otherwise). Identical replay -> changed=False."""

    @abstractmethod
    def invalidate_edge(self, edge_id: str) -> GraphChange:
        """Mark INVALIDATED (kept for history, never deleted).
        Unknown edge_id -> KeyError. Already invalidated -> changed=False."""

    @abstractmethod
    def get_entity(self, entity_id: str) -> Entity | None: ...

    @abstractmethod
    def get_edge(self, edge_id: str) -> Relationship | None: ...

    @abstractmethod
    def get_neighbors(self, entity_id: str) -> list[Relationship]:
        """Outgoing edges, sorted by edge_id."""

    @abstractmethod
    def snapshot(self) -> GraphSnapshot:
        """Immutable, versioned view. Same content -> same version string."""