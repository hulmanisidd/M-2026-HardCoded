"""P2 graph-internal types."""
from enum import StrEnum
from typing import NamedTuple

from contracts import ContractModel


class ChangeKind(StrEnum):
    ENTITY_ADDED = "entity_added"
    ENTITY_UPDATED = "entity_updated"
    ENTITY_REMOVED = "entity_removed"
    EDGE_ADDED = "edge_added"
    EDGE_UPDATED = "edge_updated"
    EDGE_INVALIDATED = "edge_invalidated"
    SCOPE_MARKED_UNKNOWN = "scope_marked_unknown"
    COLLECTION_COMPLETED = "collection_completed"


class GraphChange(ContractModel):
    """changed=False means the write was a replay (idempotent no-op).
    version is the graph version AFTER the write, so P5 can tag results.

    For a scope-wide write (SCOPE_MARKED_UNKNOWN), subject_id is Scope.key and
    changed=True means at least one edge changed status."""

    kind: ChangeKind
    subject_id: str
    changed: bool
    version: str


class Scope(NamedTuple):
    """A collection scope, as P1 reports it in COLLECTION_* events."""

    account_id: str
    source_api: str

    @property
    def key(self) -> str:
        return f"{self.account_id}|{self.source_api}"