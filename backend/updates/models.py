"""P5 data types for graph update coordination."""
from __future__ import annotations

from enum import StrEnum

from contracts.base import ContractModel


class UpdateStrategy(StrEnum):
    """How the coordinator brought its path index up to date."""

    NONE = "none"                # nothing was recomputed (rejected / ignored)
    SKIPPED = "skipped"          # change proven unrelated to every known route
    INCREMENTAL = "incremental"  # only the paths using an invalidated edge dropped
    FULL = "full"                # complete bounded path discovery re-run


class UpdateResult(ContractModel):
    """What the coordinator did in response to one GraphChange."""

    applied: bool
    reason: str
    graph_version: str
    recomputed_path_ids: tuple[str, ...] = ()
    dropped_path_ids: tuple[str, ...] = ()
    strategy: UpdateStrategy = UpdateStrategy.NONE
