
"""Immutable, versioned graph snapshot and transition evaluation interface."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    model_validator,
)
from .base import ContractModel
from .entities import Entity
from .paths import Feasibility
from .relationships import EdgeStatus, Relationship
from pydantic import BaseModel


class TransitionResult(BaseModel):
    """Result of evaluating one specific graph edge."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    edge_id: str
    status: Feasibility
    reason: str
    evidence_ids: tuple[str, ...] = ()


class GraphSnapshot(ContractModel):
    """Immutable graph data with deterministic lookups and simulation forks."""

    version: str = Field(min_length=1)
    created_at: AwareDatetime
    entities: tuple[Entity, ...] = ()
    edges: tuple[Relationship, ...] = ()

    _entity_index: dict[str, Entity] = PrivateAttr(default_factory=dict)
    _edge_index: dict[str, Relationship] = PrivateAttr(default_factory=dict)
    _outgoing: dict[str, tuple[Relationship, ...]] = PrivateAttr(
        default_factory=dict
    )

    @model_validator(mode="after")
    def check_integrity(self) -> GraphSnapshot:
        entity_ids = [entity.entity_id for entity in self.entities]
        if len(entity_ids) != len(set(entity_ids)):
            raise ValueError("duplicate entity_id in snapshot")

        edge_ids = [edge.edge_id for edge in self.edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("duplicate edge_id in snapshot")

        known = set(entity_ids)
        for edge in self.edges:
            if edge.source_id not in known or edge.target_id not in known:
                raise ValueError(
                    f"edge {edge.edge_id} references an unknown entity"
                )
        return self

    def model_post_init(self, __context: Any) -> None:
        self._entity_index = {
            entity.entity_id: entity for entity in self.entities
        }
        self._edge_index = {edge.edge_id: edge for edge in self.edges}

        outgoing: dict[str, list[Relationship]] = {}
        for edge in self.edges:
            outgoing.setdefault(edge.source_id, []).append(edge)

        self._outgoing = {
            entity_id: tuple(sorted(edges, key=lambda edge: edge.edge_id))
            for entity_id, edges in outgoing.items()
        }

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

    def get_neighbors(self, entity_id: str) -> list[Relationship]:
        """Return outgoing edges in deterministic order."""
        return list(self.outgoing_edges(entity_id))

    def check_transition(
        self, edge_id: str, context: dict
    ) -> TransitionResult:
        """Evaluate known edge status and validity; do not infer authorization."""
        edge = self.get_edge(edge_id)

        if edge is None:
            return TransitionResult(
                edge_id=edge_id,
                status=Feasibility.BLOCKED,
                reason="edge_not_found",
            )

        if edge.status == EdgeStatus.INVALIDATED:
            return TransitionResult(
                edge_id=edge_id,
                status=Feasibility.BLOCKED,
                reason="edge_invalidated",
                evidence_ids=edge.evidence_ids,
            )

        if edge.valid_from and self.created_at < edge.valid_from:
            return TransitionResult(
                edge_id=edge_id,
                status=Feasibility.BLOCKED,
                reason="edge_not_yet_valid",
                evidence_ids=edge.evidence_ids,
            )

        if edge.valid_until and self.created_at >= edge.valid_until:
            return TransitionResult(
                edge_id=edge_id,
                status=Feasibility.BLOCKED,
                reason="edge_expired",
                evidence_ids=edge.evidence_ids,
            )

        if edge.status != EdgeStatus.CONFIRMED:
            return TransitionResult(
                edge_id=edge_id,
                status=Feasibility.CONDITIONAL,
                reason=f"edge_status_{edge.status.value}",
                evidence_ids=edge.evidence_ids,
            )

        if edge.conditions:
            return TransitionResult(
                edge_id=edge_id,
                status=Feasibility.CONDITIONAL,
                reason="conditions_require_evaluation",
                evidence_ids=edge.evidence_ids,
            )

        return TransitionResult(
            edge_id=edge_id,
            status=Feasibility.FEASIBLE_UNDER_MODEL,
            reason="confirmed_edge_without_unresolved_conditions",
            evidence_ids=edge.evidence_ids,
        )

    def fork(
        self,
        removed_edge_ids: Iterable[str],
        new_version: str | None = None,
    ) -> GraphSnapshot:
        """Return a new snapshot with selected edges removed."""
        removed = frozenset(removed_edge_ids)
        unknown = sorted(edge_id for edge_id in removed
                         if edge_id not in self._edge_index)

        if unknown:
            raise ValueError(f"unknown edge ids: {unknown}")

        if new_version is None:
            digest = hashlib.sha256(
                "\x1f".join(sorted(removed)).encode()
            ).hexdigest()[:8]
            new_version = f"{self.version}+fork-{digest}"

        return GraphSnapshot(
            version=new_version,
            created_at=self.created_at,
            entities=self.entities,
            edges=tuple(
                edge for edge in self.edges if edge.edge_id not in removed
            ),
        )
