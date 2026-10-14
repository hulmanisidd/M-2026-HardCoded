"""Public entry points for Attack Path Discovery (P3)."""

from collections.abc import Iterable

from contracts.paths import AttackPath, PathOptions, SearchStats, make_path_id

from .explanations import collect_evidence, explain_path
from .models import GraphReader, PathSearchResult
from .traversal import traverse
from .validator import combine_statuses


def discover_paths(
    graph: GraphReader,
    entry_points: Iterable[str],
    targets: Iterable[str],
    options: PathOptions | None = None,
) -> PathSearchResult:
    """Bounded simple-path discovery with statistics.

    options.max_paths is a total cap across all entry points. If the cap is
    already full when another entry point is reached, truncation is reported
    conservatively.
    """
    options = options or PathOptions()
    entries = tuple(dict.fromkeys(entry_points))
    target_ids = tuple(dict.fromkeys(targets))

    paths: list[AttackPath] = []
    seen: set[str] = set()
    blocked_rejected = 0
    truncation_reason: str | None = None

    for entry in entries:
        remaining = options.max_paths - len(paths)
        if remaining <= 0:
            truncation_reason = truncation_reason or "max_paths"
            break

        outcome = traverse(
            graph, entry, target_ids, options.model_copy(update={"max_paths": remaining})
        )
        blocked_rejected += outcome.blocked_rejected
        if outcome.truncated:
            truncation_reason = truncation_reason or outcome.truncation_reason

        for raw in outcome.paths:
            path_id = make_path_id(raw.edge_ids)
            if path_id in seen:  # equivalent path already recorded
                continue
            seen.add(path_id)
            status = combine_statuses(t.status for t in raw.transitions)
            paths.append(
                AttackPath(
                    path_id=path_id,
                    graph_version=graph.version,
                    entry_node_id=raw.node_ids[0],
                    target_node_id=raw.node_ids[-1],
                    node_ids=raw.node_ids,
                    edge_ids=raw.edge_ids,
                    feasibility_status=status,
                    evidence_ids=collect_evidence(raw),
                    explanations=explain_path(graph, raw, status),
                )
            )

    paths.sort(key=lambda p: (len(p.edge_ids), p.node_ids))
    return PathSearchResult(
        graph_version=graph.version,
        paths=tuple(paths),
        stats=SearchStats(
            truncated=truncation_reason is not None,
            truncation_reason=truncation_reason,
            paths_found=len(paths),
            blocked_transitions_rejected=blocked_rejected,
        ),
    )


def find_paths(
    snapshot: GraphReader,
    entry_points: Iterable[str],
    targets: Iterable[str],
    options: PathOptions | None = None,
) -> list[AttackPath]:
    """Contract signature from the brief: find_paths(snapshot, entries, targets, options)."""
    return list(discover_paths(snapshot, entry_points, targets, options).paths)