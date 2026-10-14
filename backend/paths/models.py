"""P3 (Attack Path Discovery) internal models.

Section A mirrors the shared contracts from the handoff brief (sections 9.3/9.4).
It is TEMPORARY: contracts/ is still empty. When the team agrees the real
contracts, delete Section A and re-export from `contracts` instead, so the rest
of backend/paths does not change.

Section B (options, stats, GraphReader) is owned by P3.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------
# Section A: TEMPORARY stand-ins for contracts/ (brief sections 9.3, 9.4)
# --------------------------------------------------------------------------
class EdgeStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"
    INVALIDATED = "INVALIDATED"


class Feasibility(str, Enum):
    FEASIBLE_UNDER_MODEL = "FEASIBLE_UNDER_MODEL"
    CONDITIONAL = "CONDITIONAL"
    BLOCKED = "BLOCKED"


class Relationship(BaseModel):
    model_config = ConfigDict(frozen=True)

    edge_id: str
    source_id: str
    relation_type: str
    target_id: str
    conditions: dict = Field(default_factory=dict)
    status: EdgeStatus
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class AttackPath(BaseModel):
    model_config = ConfigDict(frozen=True)

    path_id: str
    graph_version: str
    entry_node_id: str
    target_node_id: str
    node_ids: list[str]
    edge_ids: list[str]
    feasibility_status: Feasibility
    evidence_ids: list[str] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)


class TransitionResult(BaseModel):
    """ASSUMED shape of P2's check_transition() result. Confirm with P2."""

    model_config = ConfigDict(frozen=True)

    status: Feasibility
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Section B: owned by P3
# --------------------------------------------------------------------------
class PathOptions(BaseModel):
    """Declared scope and limits for one search (brief section 0.2)."""

    model_config = ConfigDict(frozen=True)

    max_depth: int = Field(default=5, ge=1, description="Max edges per path")
    max_paths: int = Field(default=1000, ge=1, description="Stop after this many")
    allowed_relation_types: frozenset[str] | None = None  # None = all types
    include_blocked: bool = False  # True: also return BLOCKED paths for debugging
    context: dict = Field(default_factory=dict)  # passed to check_transition


class SearchStats(BaseModel):
    """Truncation must be reported, never silent (brief section 0.2)."""

    truncated: bool = False
    truncation_reason: str | None = None  # "max_paths" | "max_depth" | ...
    paths_found: int = 0
    blocked_transitions_rejected: int = 0


@runtime_checkable
class GraphReader(Protocol):
    """The read-only slice of P2's snapshot that P3 depends on.

    P3 never imports P2 internals or Neo4j code, only this protocol.
    """

    @property
    def version(self) -> str: ...

    def get_neighbors(self, entity_id: str) -> list[Relationship]: ...

    def check_transition(
        self, source_id: str, target_id: str, context: dict
    ) -> TransitionResult: ...