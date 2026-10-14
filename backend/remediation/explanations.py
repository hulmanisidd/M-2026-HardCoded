"""P4 explanations: human-readable text built only from existing contract fields.

Nothing here computes or changes a score; it only describes what scoring.py produced.
"""
from __future__ import annotations

from contracts import RiskAssessment

SCORE_NOTE = "relative route score, not a probability"


def _fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.2f}"


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