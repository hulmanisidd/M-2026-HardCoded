"""AttackPath: an ordered, explainable route through a GraphSnapshot (brief section 9.4)."""
import hashlib
from enum import StrEnum

from pydantic import Field, model_validator

from .base import ContractModel


class FeasibilityStatus(StrEnum):
    """Whether a path can be traversed, judged under the modeled rules only.

    FEASIBLE_UNDER_MODEL - every edge is present, current, and unconditional
                           according to the modeled authorization rules.
    CONDITIONAL          - at least one edge is stale/unknown or carries
                           conditions we could not verify.
    BLOCKED              - at least one edge is invalidated or outside its
                           validity window.

    None of these mean an attack happened.
    """

    FEASIBLE_UNDER_MODEL = "feasible_under_model"
    CONDITIONAL = "conditional"
    BLOCKED = "blocked"


def make_path_id(edge_ids: tuple[str, ...]) -> str:
    """Stable path id derived only from the ordered edge ids.

    The graph version is deliberately NOT part of the id, so the same route
    keeps its id across graph updates and P5 can track it over time.
    """
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
    def _check_shape(self) -> "AttackPath":
        if len(self.node_ids) != len(self.edge_ids) + 1:
            raise ValueError("node_ids must have exactly one more item than edge_ids")
        if self.node_ids[0] != self.entry_node_id:
            raise ValueError("first node must be the entry node")
        if self.node_ids[-1] != self.target_node_id:
            raise ValueError("last node must be the target node")
        if len(set(self.node_ids)) != len(self.node_ids):
            raise ValueError("path revisits a node")
        if len(set(self.edge_ids)) != len(self.edge_ids):
            raise ValueError("path reuses an edge")
        return self