
"""P5 data types for graph update coordination."""
from __future__ import annotations

from contracts.base import ContractModel


class UpdateResult(ContractModel):
    """What the coordinator did in response to one GraphChange."""

    applied: bool
    reason: str
    graph_version: str
    recomputed_path_ids: tuple[str, ...] = ()
    dropped_path_ids: tuple[str, ...] = ()
