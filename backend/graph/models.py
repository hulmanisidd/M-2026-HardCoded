"""P2 graph-internal types."""
from enum import StrEnum

from contracts import ContractModel


class ChangeKind(StrEnum):
    ENTITY_ADDED = "entity_added"
    ENTITY_UPDATED = "entity_updated"
    EDGE_ADDED = "edge_added"
    EDGE_UPDATED = "edge_updated"
    EDGE_INVALIDATED = "edge_invalidated"


class GraphChange(ContractModel):
    """changed=False means the write was a replay (idempotent no-op).
    version is the graph version AFTER the write, so P5 can tag results."""

    kind: ChangeKind
    subject_id: str
    changed: bool
    version: str