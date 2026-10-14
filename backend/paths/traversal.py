"""Bounded simple-path DFS. Read-only: never mutates the graph."""

from collections.abc import Iterable
from dataclasses import dataclass

from contracts.graph import TransitionResult
from contracts.paths import Feasibility, PathOptions

from .models import DEFAULT_ATTACK_RELATIONS, GraphReader


@dataclass(frozen=True)
class RawPath:
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    transitions: tuple[TransitionResult, ...]


@dataclass(frozen=True)
class TraversalOutcome:
    paths: tuple[RawPath, ...]
    truncated: bool
    truncation_reason: str | None
    blocked_rejected: int


def traverse(
    graph: GraphReader,
    entry_id: str,
    target_ids: Iterable[str],
    options: PathOptions,
) -> TraversalOutcome:
    """Enumerate simple paths entry -> any target within the options' limits.

    - A path stops at the first target it reaches (it is not extended).
    - Nodes are never revisited, so cycles cannot loop.
    - Blocked edges are skipped and counted, unless options.include_blocked.
    - Truncation is reported: "max_paths" (hit the cap) or "max_depth"
      (some unexplored edge existed at the depth limit; conservative).
    """
    if options.allowed_relation_types is None:
        allowed = DEFAULT_ATTACK_RELATIONS
    else:
        allowed = frozenset(str(r) for r in options.allowed_relation_types)
    targets = frozenset(target_ids)

    found: list[RawPath] = []
    blocked_rejected = 0
    depth_cut = False
    stopped = False

    def walk(node, nodes, edges, transitions):
        nonlocal blocked_rejected, depth_cut, stopped

        candidates = [
            e
            for e in graph.get_neighbors(node)
            if str(e.relation_type) in allowed and e.target_id not in nodes
        ]
        if len(edges) >= options.max_depth:
            if candidates:
                depth_cut = True
            return

        for edge in candidates:
            result = graph.check_transition(edge.edge_id, options.context)
            if result.status is Feasibility.BLOCKED and not options.include_blocked:
                blocked_rejected += 1
                continue

            new_nodes = nodes + (edge.target_id,)
            new_edges = edges + (edge.edge_id,)
            new_trans = transitions + (result,)

            if edge.target_id in targets:
                if len(found) >= options.max_paths:
                    stopped = True
                    return
                found.append(RawPath(new_nodes, new_edges, new_trans))
                continue

            walk(edge.target_id, new_nodes, new_edges, new_trans)
            if stopped:
                return

    if entry_id not in targets:
        walk(entry_id, (entry_id,), (), ())

    reason = "max_paths" if stopped else ("max_depth" if depth_cut else None)
    return TraversalOutcome(
        paths=tuple(found),
        truncated=reason is not None,
        truncation_reason=reason,
        blocked_rejected=blocked_rejected,
    )