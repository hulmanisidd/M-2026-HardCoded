"""P4 risk scoring: rank_paths(paths, snapshot) -> list[RiskAssessment].

Scales: every score is in [0, 1].

IMPORTANT: `likelihood_score` is a RELATIVE ROUTE SCORE (how easy the route looks
under the model), NOT a calibrated attack probability. No validated outcome labels
exist yet (brief section 0.5), so do not present it as a probability.

Missing evidence is never turned into a normal-looking number:
  - an edge with status UNKNOWN, or an edge/entity missing from the snapshot
    -> likelihood_score=None, risk_score=None, confidence="unknown", listed in `unknowns`.

Formula (documented, configurable via RiskConfig):
    likelihood = length_factor * prod(edge_factor)
    length_factor = max(min_length_factor, 1 - per_hop_decay * (hops - 1))
    edge_factor   = status weight (confirmed/inferred/stale) * constrained_factor if edge has conditions
    risk          = likelihood * impact
"""
from __future__ import annotations

from dataclasses import dataclass, field

from contracts import (
    AttackPath,
    Criticality,
    EdgeStatus,
    FeasibilityStatus,
    GraphSnapshot,
    RiskAssessment,
)


@dataclass(frozen=True)
class RiskConfig:
    criticality_impact: dict = field(default_factory=lambda: {
        Criticality.CRITICAL: 1.0,
        Criticality.HIGH: 0.8,
        Criticality.MEDIUM: 0.5,
        Criticality.LOW: 0.2,
    })
    status_weight: dict = field(default_factory=lambda: {
        EdgeStatus.CONFIRMED: 1.0,
        EdgeStatus.INFERRED: 0.6,
        EdgeStatus.STALE: 0.4,
    })
    per_hop_decay: float = 0.15       # each extra transition makes the route harder
    min_length_factor: float = 0.2    # floor so long paths never reach zero
    constrained_factor: float = 0.7   # an edge with conditions is harder to use


def _unknown(path: AttackPath, impact: float, unknowns: list[str], reasons: list[str]) -> RiskAssessment:
    return RiskAssessment(
        path_id=path.path_id,
        graph_version=path.graph_version,
        likelihood_score=None,
        impact_score=impact,
        confidence="unknown",
        risk_score=None,
        reasons=reasons,
        unknowns=unknowns,
    )


def assess_path(path: AttackPath, snapshot: GraphSnapshot, config: RiskConfig | None = None) -> RiskAssessment:
    cfg = config or RiskConfig()
    reasons: list[str] = []
    unknowns: list[str] = []

    if path.graph_version != snapshot.version:
        unknowns.append(f"path computed on graph {path.graph_version}, snapshot is {snapshot.version}")

    target = snapshot.get_entity(path.target_node_id)
    if target is None:
        unknowns.append(f"target entity {path.target_node_id} not in snapshot")
        # impact_score is required by the contract; 0.0 is a placeholder only.
        # risk_score stays None, so this can never rank as "safe".
        return _unknown(path, 0.0, unknowns, reasons)
    impact = cfg.criticality_impact[target.criticality]
    reasons.append(f"target {target.name} criticality={target.criticality.value} -> impact {impact}")

    if path.feasibility_status == FeasibilityStatus.BLOCKED:
        reasons.append("path is BLOCKED under the model: no risk contribution")
        return RiskAssessment(
            path_id=path.path_id, graph_version=path.graph_version,
            likelihood_score=0.0, impact_score=impact, confidence="high",
            risk_score=0.0, reasons=reasons, unknowns=unknowns,
        )

    likelihood = max(cfg.min_length_factor, 1 - cfg.per_hop_decay * (len(path.edge_ids) - 1))
    reasons.append(f"{len(path.edge_ids)} hop(s) -> length factor {likelihood:.2f}")

    weakest = "high"  # drops to medium / low as evidence weakens
    for edge_id in path.edge_ids:
        edge = snapshot.get_edge(edge_id)
        if edge is None:
            unknowns.append(f"edge {edge_id} not in snapshot")
            continue
        if edge.status == EdgeStatus.UNKNOWN:
            unknowns.append(f"edge {edge_id} has UNKNOWN status")
            continue
        if edge.status == EdgeStatus.INVALIDATED:
            unknowns.append(f"edge {edge_id} is INVALIDATED but still used by the path (stale path?)")
            continue
        weight = cfg.status_weight[edge.status]
        likelihood *= weight
        if edge.status == EdgeStatus.INFERRED:
            weakest = "medium" if weakest == "high" else weakest
            reasons.append(f"edge {edge_id} is INFERRED (x{weight})")
        elif edge.status == EdgeStatus.STALE:
            weakest = "low"
            reasons.append(f"edge {edge_id} is STALE (x{weight})")
        if edge.conditions:
            likelihood *= cfg.constrained_factor
            weakest = "medium" if weakest == "high" else weakest
            reasons.append(f"edge {edge_id} has conditions (x{cfg.constrained_factor})")

    if path.feasibility_status == FeasibilityStatus.CONDITIONAL:
        weakest = "low" if weakest == "medium" else ("medium" if weakest == "high" else weakest)
        reasons.append("path feasibility is CONDITIONAL (unverified transitions)")

    if unknowns:
        return _unknown(path, impact, unknowns, reasons)

    likelihood = round(min(max(likelihood, 0.0), 1.0), 6)
    return RiskAssessment(
        path_id=path.path_id, graph_version=path.graph_version,
        likelihood_score=likelihood, impact_score=impact, confidence=weakest,
        risk_score=round(likelihood * impact, 6), reasons=reasons, unknowns=unknowns,
    )


def rank_paths(paths: list[AttackPath], snapshot: GraphSnapshot,
               config: RiskConfig | None = None) -> list[RiskAssessment]:
    """Highest risk first. Unknown-risk paths sort last but are NEVER dropped."""
    assessed = [assess_path(p, snapshot, config) for p in paths]
    return sorted(
        assessed,
        key=lambda a: (a.risk_score is None, -(a.risk_score or 0.0), a.path_id),
    )