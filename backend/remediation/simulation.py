"""P4 fix simulation. Works on a forked COPY of the snapshot; the source is never mutated.

Path discovery is injected (`PathFinder`) so P4 does not import P3 internals. It must be
deterministic and match the brief: find_paths(snapshot) -> list[AttackPath]. Wrap P3's
`find_paths(snapshot, entry_points, targets, options)` with functools.partial / a lambda.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable

from contracts import (
    AttackPath,
    FeasibilityStatus,
    GraphSnapshot,
    RemediationPlan,
    RemediationRecommendation,
    SimulationResult,
    VerificationStatus,
)

from .candidates import Candidate
from .scoring import RiskConfig, rank_paths

PathFinder = Callable[[GraphSnapshot], list[AttackPath]]


def _live(paths: list[AttackPath]) -> list[AttackPath]:
    return [p for p in paths if p.feasibility_status != FeasibilityStatus.BLOCKED]


def simulate_plan(snapshot: GraphSnapshot, plan: RemediationPlan,
                  find_paths: PathFinder) -> tuple[SimulationResult, list[AttackPath]]:
    """Apply `plan` to a forked copy, re-run path discovery, return (result, residual paths)."""
    if plan.base_version != snapshot.version:
        raise ValueError(f"plan is for {plan.base_version}, snapshot is {snapshot.version}")
    forked = snapshot.fork(plan.removed_edge_ids)
    before = _live(find_paths(snapshot))
    after = _live(find_paths(forked))
    result = SimulationResult(
        plan_id=plan.id, before_version=snapshot.version, after_version=forked.version,
        paths_before=tuple(sorted(p.path_id for p in before)),
        paths_after=tuple(sorted(p.path_id for p in after)),
    )
    return result, after


def recommend(candidate: Candidate, snapshot: GraphSnapshot, find_paths: PathFinder,
              config: RiskConfig | None = None) -> RemediationRecommendation:
    """Simulate one candidate and return a SIMULATED recommendation (never VERIFIED: that is P5's job)."""
    result, residual = simulate_plan(snapshot, candidate.plan, find_paths)
    before_paths = _live(find_paths(snapshot))
    assessments = {a.path_id: a for a in rank_paths(before_paths, snapshot, config)}

    known_total = sum(a.risk_score for a in assessments.values() if a.risk_score is not None)
    blocked_risk = sum(assessments[i].risk_score or 0.0 for i in result.blocked_path_ids if i in assessments)
    unknown_ids = [i for i, a in assessments.items() if a.risk_score is None]

    assumptions = list(candidate.assumptions)
    assumptions.append("simulation = edge removal on a graph copy; real AWS semantics not re-evaluated")
    if unknown_ids:
        assumptions.append(f"{len(unknown_ids)} path(s) have unknown risk and are excluded from risk_reduction")
    reduction = round(blocked_risk / known_total, 6) if known_total > 0 else None

    return RemediationRecommendation(
        recommendation_id="rec_" + hashlib.sha256(
            f"{snapshot.version}|{candidate.candidate_id}".encode()).hexdigest()[:12],
        graph_version=snapshot.version,
        action_type=candidate.action_type,
        target_id=candidate.target_id,
        estimated_cost=candidate.cost,
        expected_blocked_path_ids=list(result.blocked_path_ids),
        residual_path_ids=sorted(p.path_id for p in residual),
        estimated_risk_reduction=reduction,
        assumptions=assumptions,
        verification_status=VerificationStatus.SIMULATED,
    )