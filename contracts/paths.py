"""Attack path (brief 9.4) plus search options/stats. Owner: P3."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Feasibility(str, Enum):
    FEASIBLE_UNDER_MODEL = "FEASIBLE_UNDER_MODEL"
    CONDITIONAL = "CONDITIONAL"
    BLOCKED = "BLOCKED"


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


class PathOptions(BaseModel):
    """Declared scope and limits for one search (brief 0.2)."""

    model_config = ConfigDict(frozen=True)

    max_depth: int = Field(default=5, ge=1)       # max edges per path
    max_paths: int = Field(default=1000, ge=1)
    allowed_relation_types: frozenset[str] | None = None  # None = all types
    include_blocked: bool = False                 # True: also return BLOCKED paths
    context: dict = Field(default_factory=dict)   # passed to check_transition


class SearchStats(BaseModel):
    """Truncation is reported, never silent (brief 0.2)."""

    truncated: bool = False
    truncation_reason: str | None = None  # "max_paths" | "max_depth"
    paths_found: int = 0
    blocked_transitions_rejected: int = 0