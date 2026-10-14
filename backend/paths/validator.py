"""Combine per-edge transition results into one path-level verdict."""

from collections.abc import Iterable

from contracts.graph import TransitionResult
from contracts.paths import Feasibility

from .models import GraphReader


def combine_statuses(statuses: Iterable[Feasibility]) -> Feasibility:
    """Worst status wins: BLOCKED > CONDITIONAL > FEASIBLE_UNDER_MODEL."""
    items = list(statuses)
    if not items:
        raise ValueError("cannot combine an empty list of statuses")
    if Feasibility.BLOCKED in items:
        return Feasibility.BLOCKED
    if Feasibility.CONDITIONAL in items:
        return Feasibility.CONDITIONAL
    return Feasibility.FEASIBLE_UNDER_MODEL


def validate_path(
    graph: GraphReader, edge_ids: Iterable[str], context: dict
) -> tuple[Feasibility, tuple[TransitionResult, ...]]:
    """Check every edge via the graph's own check_transition."""
    results = tuple(graph.check_transition(e, context) for e in edge_ids)
    return combine_statuses(r.status for r in results), results