
"""Canonical attack-path contracts and search controls."""

import hashlib
from enum import StrEnum

from pydantic import Field, model_validator

from .base import ContractModel


class FeasibilityStatus(StrEnum):
    FEASIBLE_UNDER_MODEL = "feasible_under_model"
    CONDITIONAL = "conditional"
    BLOCKED = "blocked"


# Backwards-compatible name used by the existing graph contract.
Feasibility = FeasibilityStatus


def make_path_id(edge_ids: tuple[str, ...]) -> str:
    key = "\x1f".join(edge_ids)
    return "p_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class AttackPath(ContractModel):
    path_id: str = Field(min_length=1)
    graph_version: str = Field(min_length=1)
    entry_node_id: str = Field(min_length=1)
    target_node_id: str = Field(min_length=1)
    node_ids: tuple[str, ...] = Field(min_length=2)
    edge_ids: tuple[str, ...] = Field(min_length=1)
    feasibility_status: FeasibilityStatus
    evidence_ids: tuple[str, ...] = ()
    explanations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def check_shape(self) -> "AttackPath":
        if len(self.node_ids) != len(self.edge_ids) + 1:
            raise ValueError(
                "node_ids must have exactly one more item than edge_ids"
            )
        if self.node_ids[0] != self.entry_node_id:
            raise ValueError("first node must be the entry node")
        if self.node_ids[-1] != self.target_node_id:
            raise ValueError("last node must be the target node")
        if len(set(self.node_ids)) != len(self.node_ids):
            raise ValueError("path revisits a node")
        if len(set(self.edge_ids)) != len(self.edge_ids):
            raise ValueError("path reuses an edge")
        return self


class PathOptions(ContractModel):
    max_depth: int = Field(default=5, ge=1)
    max_paths: int = Field(default=1000, ge=1)
    allowed_relation_types: frozenset[str] | None = None
    include_blocked: bool = False
    context: dict = Field(default_factory=dict)


class SearchStats(ContractModel):
    truncated: bool = False
    truncation_reason: str | None = None
    paths_found: int = 0
    blocked_transitions_rejected: int = 0
