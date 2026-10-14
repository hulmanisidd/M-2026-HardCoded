"""P5 data types. These live here (not in contracts/) until the team agrees
to promote them. They reuse the shared ContractModel base: frozen + no extra fields.
"""
from __future__ import annotations

from pydantic import Field

from contracts.base import ContractModel


class GraphChange(ContractModel):
    """The map went from from_version to to_version; these links changed."""

    from_version: str = Field(min_length=1)
    to_version: str = Field(min_length=1)
    added_edge_ids: tuple[str, ...] = ()
    removed_edge_ids: tuple[str, ...] = ()
    changed_edge_ids: tuple[str, ...] = ()  # same edge, new status/conditions

    @property
    def touched_edge_ids(self) -> frozenset[str]:
        """Edges whose change can break or alter an existing path."""
        return frozenset(self.removed_edge_ids) | frozenset(self.changed_edge_ids)


class UpdateResult(ContractModel):
    """What the coordinator did in response to one GraphChange."""

    applied: bool                      # False when the change was ignored
    reason: str                        # e.g. "applied", "duplicate", "stale_version"
    graph_version: str                 # version the results now belong to
    recomputed_path_ids: tuple[str, ...] = ()
    dropped_path_ids: tuple[str, ...] = ()