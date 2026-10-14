"""Path-discovery models and read-only graph interface.

Shared domain models come from the canonical contracts package.
P3-only helper types (search result, default relation set) live here.
"""

from typing import Protocol, runtime_checkable

from contracts.base import ContractModel
from contracts.graph import GraphSnapshot, TransitionResult
from contracts.paths import AttackPath, Feasibility, PathOptions, SearchStats
from contracts.relationships import EdgeStatus, Relationship
from contracts.vocab import RelationType

# Relations that represent an attacker *step*. Structural links
# (member_of, has_policy) are excluded by default; callers can override via
# PathOptions.allowed_relation_types.
DEFAULT_ATTACK_RELATIONS: frozenset[str] = frozenset(
    str(r)
    for r in RelationType
    if r not in (RelationType.MEMBER_OF, RelationType.HAS_POLICY)
)


@runtime_checkable
class GraphReader(Protocol):
    """Read-only interface consumed by path discovery."""

    @property
    def version(self) -> str: ...

    def get_neighbors(self, entity_id: str) -> list[Relationship]: ...

    def check_transition(
        self, edge_id: str, context: dict
    ) -> TransitionResult: ...


class PathSearchResult(ContractModel):
    """What the engine returns: paths plus honest search statistics."""

    graph_version: str
    paths: tuple[AttackPath, ...] = ()
    stats: SearchStats = SearchStats()


__all__ = [
    "AttackPath",
    "DEFAULT_ATTACK_RELATIONS",
    "EdgeStatus",
    "Feasibility",
    "GraphReader",
    "GraphSnapshot",
    "PathOptions",
    "PathSearchResult",
    "Relationship",
    "SearchStats",
    "TransitionResult",
]