"""Human-readable, evidence-linked explanations for discovered paths."""

from contracts.paths import Feasibility

from .models import GraphReader
from .traversal import RawPath


def explain_path(
    graph: GraphReader, raw: RawPath, status: Feasibility
) -> tuple[str, ...]:
    lines: list[str] = []
    for i, (edge_id, result) in enumerate(zip(raw.edge_ids, raw.transitions)):
        src, dst = raw.node_ids[i], raw.node_ids[i + 1]
        edge = next(
            (e for e in graph.get_neighbors(src) if e.edge_id == edge_id), None
        )
        relation = str(edge.relation_type) if edge else "unknown_relation"
        lines.append(
            f"Step {i + 1}: {src} --{relation}--> {dst} "
            f"is {result.status.value} ({result.reason})"
        )

    if status is Feasibility.FEASIBLE_UNDER_MODEL:
        lines.append("Overall: every step is confirmed under the modeled rules.")
    elif status is Feasibility.CONDITIONAL:
        lines.append(
            "Overall: at least one step is unconfirmed or conditional; "
            "treat as unverified, not safe."
        )
    else:
        lines.append("Overall: at least one step is blocked.")
    lines.append("This is a modeled possibility, not evidence of an attack.")
    return tuple(lines)


def collect_evidence(raw: RawPath) -> tuple[str, ...]:
    """Unique evidence ids across all transitions, in path order."""
    seen: dict[str, None] = {}
    for result in raw.transitions:
        for evidence_id in result.evidence_ids:
            seen.setdefault(evidence_id, None)
    return tuple(seen)