"""Path-discovery models and read-only graph interface.

Shared domain models come from the canonical contracts package.
Search options and statistics remain owned by the path-discovery backend.
"""

from typing import Protocol, runtime_checkable

from pydantic import Field

from contracts.graph import GraphSnapshot, TransitionResult
from contracts.paths import AttackPath, Feasibility, PathOptions, SearchStats
from contracts.relationships import EdgeStatus, Relationship


@runtime_checkable
class GraphReader(Protocol):
    """Read-only interface consumed by path discovery."""

    @property
    def version(self) -> str: ...

    def get_neighbors(self, entity_id: str) -> list[Relationship]: ...

    def check_transition(
        self, edge_id: str, context: dict
    ) -> TransitionResult: ...


__all__ = [
    "AttackPath",
    "EdgeStatus",
    "Feasibility",
    "GraphReader",
    "GraphSnapshot",
    "PathOptions",
    "Relationship",
    "SearchStats",
    "TransitionResult",
]
