"""Read-only graph interface that P3/P4 consume. Owner: P2 implements it.

Deviation from brief 9.7: check_transition takes an edge_id, not (source, target),
so parallel edges between the same two nodes are checked individually.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from .paths import Feasibility
from .relationships import Relationship


class TransitionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    edge_id: str
    status: Feasibility
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


@runtime_checkable
class GraphSnapshot(Protocol):
    """An immutable, versioned view. P3 and P4 must never mutate it."""

    @property
    def version(self) -> str: ...

    def get_neighbors(self, entity_id: str) -> list[Relationship]:
        """Outgoing edges of entity_id, in a deterministic order."""
        ...

    def check_transition(self, edge_id: str, context: dict) -> TransitionResult: ...