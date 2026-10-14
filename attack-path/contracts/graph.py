"""GraphSnapshot: an immutable, versioned view of the attack-path graph."""
import hashlib
from collections.abc import Iterable
from typing import Any

from pydantic import AwareDatetime, Field, PrivateAttr, model_validator

from .base import ContractModel
from .entities import Entity
from .relationships import Relationship


class GraphSnapshot(ContractModel):
    version: str = Field(min_length=1)
    created_at: AwareDatetime  # freshness is evaluated as of this time
    entities: tuple[Entity, ...] = ()
    edges: tuple[Relationship, ...] = ()

    # Lookup indexes, built once after validation (not part of the contract).
    _entity_index: dict[str, Entity] = PrivateAttr(default_factory=dict)
    _edge_index: dict[str, Relationship] = PrivateAttr(default_factory=dict)
    _outgoing: dict[str, tuple[Relationship, ...]] = PrivateAttr(default_factory=dict)

    @model_validator(mode="after")
    def _check_integrity(self) -> "GraphSnapshot":
        entity_ids = [e.entity_id for e in self.entities]
        if len(entity_ids) != len(set(entity_ids)):
            raise ValueError("duplicate entity_id in snapshot")
        edge_ids = [e.edge_id for e in self.edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("duplicate edge_id in snapshot")
        known = set(entity_ids)
        for edge in self.edges:
            if edge.source_id not in known or edge.target_id not in known:
                raise ValueError(f"edge {edge.edge_id} references an unknown entity")
        return self

    def model_post_init(self, __context: Any) -> None:
        self._entity_index = {e.entity_id: e for e in self.entities}
        self._edge_index = {e.edge_id: e for e in self.edges}
        outgoing: dict[str, list[Relationship]] = {}
        for edge in self.edges:
            outgoing.setdefault(edge.source_id, []).append(edge)
        self._outgoing = {k: tuple(v) for k, v in outgoing.items()}

    # ---- lookups -------------------------------------------------------
    def get_entity(self, entity_id: str) -> Entity | None:
        return self._entity_index.get(entity_id)

    def list_entities(self) -> tuple[Entity, ...]:
        return self.entities

    def get_edge(self, edge_id: str) -> Relationship | None:
        return self._edge_index.get(edge_id)

    def list_edges(self) -> tuple[Relationship, ...]:
        return self.edges

    def outgoing_edges(self, entity_id: str) -> tuple[Relationship, ...]:
        return self._outgoing.get(entity_id, ())

    # ---- simulation ----------------------------------------------------
    def fork(
        self,
        removed_edge_ids: Iterable[str],
        new_version: str | None = None,
    ) -> "GraphSnapshot":
        """Return a NEW snapshot without the given edges; self is unchanged.

        created_at is kept, so freshness is judged at the same point in time.
        If new_version is omitted, one is derived deterministically from this
        version and the removed edge ids.
        """
        removed = frozenset(removed_edge_ids)
        unknown = sorted(i for i in removed if i not in self._edge_index)
        if unknown:
            raise ValueError(f"unknown edge ids: {unknown}")
        if new_version is None:
            digest = hashlib.sha256("\x1f".join(sorted(removed)).encode()).hexdigest()[:8]
            new_version = f"{self.version}+fork-{digest}"
        return GraphSnapshot(
            version=new_version,
            created_at=self.created_at,
            entities=self.entities,
            edges=tuple(e for e in self.edges if e.edge_id not in removed),
        )