"""P4 explanations: human-readable text built only from existing contract fields.

Nothing here computes or changes a score; it only describes what scoring.py and
optimizer.py produced.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from contracts import RemediationRecommendation, RiskAssessment

if TYPE_CHECKING:
    from backend.remediation.optimizer import OptimizerResult

SCORE_NOTE = "relative route score, not a probability"


def _fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.2f}"


def _val(x):
    return getattr(x, "value", x)


def explain_assessment(a: RiskAssessment) -> str:
    lines = [f"Path {a.path_id} (graph {a.graph_version})"]
    if a.risk_score is None:
        lines.append(f"Risk: UNKNOWN - not scored because evidence is missing; confidence {a.confidence}")
    else:
        lines.append(
            f"Risk: {_fmt(a.risk_score)} = likelihood {_fmt(a.likelihood_score)} "
            f"x impact {_fmt(a.impact_score)} ({SCORE_NOTE}); confidence {a.confidence}"
        )
    if a.reasons:
        lines.append("Factors:")
        lines.extend(f"  - {r}" for r in a.reasons)
    if a.unknowns:
        lines.append("Unknowns:")
        lines.extend(f"  - {u}" for u in a.unknowns)
    return "\n".join(lines)


def explain_fix_set(result: OptimizerResult) -> str:
    lines = [f"Chosen fixes: {len(result.chosen)} (total cost {result.total_cost:.2f}, 0-1 scale)"]
    for c in result.chosen:
        edges = ", ".join(c.plan.removed_edge_ids)
        n = len(c.covered_path_ids)
        lines.append(
            f"  - {c.candidate_id}: {_val(c.action_type)} on {c.target_id} (edge {edges}); "
            f"cost {c.cost:.2f}, disruption {c.disruption:.2f}; covers {n} path(s)"
        )
        if n > 1:
            lines.append(f"    shared root cause: this one fix blocks {n} paths")
        if c.rationale:
            lines.append(f"    why: {c.rationale}")
    b, r = result.baseline, result.residual
    lines.append(
        f"Known risk: {b.known_risk:.2f} -> {r.known_risk:.2f} "
        f"(sum of relative route scores, not probabilities)"
    )
    lines.append(f"Paths still present after fixes: {len(r.residual_path_ids)}")
    if r.unknown_path_ids:
        lines.append(f"Paths with unknown risk (not counted in totals): {len(r.unknown_path_ids)}")
    if result.rejected:
        lines.append("Rejected:")
        lines.extend(f"  - {cid}: {reason}" for cid, reason in result.rejected)
    if result.assumptions:
        lines.append("Assumptions:")
        lines.extend(f"  - {a}" for a in result.assumptions)
    return "\n".join(lines)


def explain_recommendation(r: RemediationRecommendation) -> str:
    lines = [
        f"Recommendation {r.recommendation_id} (graph {r.graph_version}) "
        f"[{_val(r.verification_status)}]",
        f"Action: {_val(r.action_type)} on {r.target_id}",
        f"Estimated cost: {_fmt(r.estimated_cost)} (0-1 assumption)",
        f"Simulated alone: blocks {len(r.expected_blocked_path_ids)} path(s), "
        f"{len(r.residual_path_ids)} path(s) remain",
        f"Estimated risk reduction: {_fmt(r.estimated_risk_reduction)} "
        f"(fraction of known baseline route risk blocked, 0-1; not a probability)",
    ]
    if r.assumptions:
        lines.append("Assumptions:")
        lines.extend(f"  - {a}" for a in r.assumptions)
    return "\n".join(lines)