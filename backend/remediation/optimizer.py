"""Greedy weighted remediation optimizer (P4).

This is a greedy approximation, NOT a globally optimal solver.
"""
from __future__ import annotations

from dataclasses import dataclass
from backend.remediation.candidates import Candidate


from backend.remediation.scoring import RiskConfig, rank_paths
from backend.remediation.candidates import generate_candidates
from backend.remediation.simulation import recommend
from contracts.remediation import RemediationRecommendation


@dataclass(frozen=True)
class OptimizerConstraints:
    """Operational rules the optimizer must respect.

    Every field defaults to "no restriction", so OptimizerConstraints()
    means unconstrained.
    """

    # Cap on the summed estimated_cost of all chosen fixes.
    max_total_cost: float | None = None
    # Cap on the disruption of any single chosen fix.
    # Use 0 to mean "no downtime allowed".
    max_disruption_per_action: float | None = None
    # Edges that must never be removed.
    forbidden_edge_ids: frozenset[str] = frozenset()
    # Action types that must never be used.
    forbidden_action_types: frozenset[str] = frozenset()
    # Edges that must be removed, even if the greedy score ranks them low.
    mandatory_edge_ids: frozenset[str] = frozenset()
    # Maximum number of fixes to choose.
    max_actions: int | None = None
    # Weight on cost in: score = risk_reduction - cost_weight * cost
    cost_weight: float = 0.0

def is_allowed(candidate: Candidate, constraints: OptimizerConstraints) -> bool:
    """True if the candidate violates none of the per-action constraints.

    Total-cost and max-actions are checked during selection, not here,
    because they depend on what has already been chosen.
    """
    if candidate.action_type in constraints.forbidden_action_types:
        return False
    if any(e in constraints.forbidden_edge_ids for e in candidate.plan.removed_edge_ids):
        return False
    if (
        constraints.max_disruption_per_action is not None
        and candidate.disruption > constraints.max_disruption_per_action
    ):
        return False
    return True


@dataclass(frozen=True)
class ResidualRisk:
    """Risk left on the graph after applying a set of fixes together."""

    known_risk: float                      # sum of risk_score over paths with a known score
    unknown_path_ids: tuple[str, ...]      # live paths whose risk could not be scored
    residual_path_ids: tuple[str, ...]     # every non-blocked path still present


def residual_risk(
    chosen: list[Candidate],
    snapshot,
    find_paths,
    config: RiskConfig | None = None,
) -> ResidualRisk:
    """Apply all chosen fixes at once on a fork, re-run path discovery, score what remains.

    Paths are scored against the SAME forked snapshot they were discovered on,
    so the graph-version check in scoring passes. Alternate routes that survive
    the fixes stay visible and count toward residual risk.
    """
    removed = sorted({e for c in chosen for e in c.plan.removed_edge_ids})
    graph = snapshot.fork(tuple(removed)) if removed else snapshot

    live = [p for p in find_paths(graph) if p.feasibility_status != "blocked"]
    assessments = rank_paths(live, graph, config)
    known = sum(a.risk_score for a in assessments if a.risk_score is not None)
    unknown = tuple(sorted(a.path_id for a in assessments if a.risk_score is None))
    return ResidualRisk(
        known_risk=known,
        unknown_path_ids=unknown,
        residual_path_ids=tuple(sorted(p.path_id for p in live)),
    )

@dataclass(frozen=True)
class OptimizerResult:
    chosen: tuple[Candidate, ...]
    baseline: ResidualRisk
    residual: ResidualRisk
    total_cost: float
    rejected: tuple[tuple[str, str], ...]   # (candidate_id, reason)
    assumptions: tuple[str, ...]


def greedy_select(
    candidates: list[Candidate],
    snapshot,
    find_paths,
    constraints: OptimizerConstraints | None = None,
    config: RiskConfig | None = None,
) -> OptimizerResult:
    """Greedy approximation: repeatedly add the fix with the best marginal score.

    Not guaranteed globally optimal.
    """
    constraints = constraints or OptimizerConstraints()
    eps = 1e-12

    rejected: list[tuple[str, str]] = []
    allowed: list[Candidate] = []
    for c in sorted(candidates, key=lambda c: c.candidate_id):
        if is_allowed(c, constraints):
            allowed.append(c)
        else:
            rejected.append((c.candidate_id, "forbidden action/edge or disruption above cap"))

    # Mandatory fixes go in first.
    chosen: list[Candidate] = [
        c for c in allowed
        if any(e in constraints.mandatory_edge_ids for e in c.plan.removed_edge_ids)
    ]
    covered = {e for c in chosen for e in c.plan.removed_edge_ids}
    unmet = sorted(constraints.mandatory_edge_ids - covered)
    total_cost = sum(c.cost for c in chosen)

    baseline = residual_risk([], snapshot, find_paths, config)
    current = residual_risk(chosen, snapshot, find_paths, config)
    chosen_ids = {c.candidate_id for c in chosen}

    while True:
        if constraints.max_actions is not None and len(chosen) >= constraints.max_actions:
            break
        best = None  # (score, candidate, trial)
        for c in allowed:
            if c.candidate_id in chosen_ids:
                continue
            if constraints.max_total_cost is not None and total_cost + c.cost > constraints.max_total_cost:
                continue
            trial = residual_risk(chosen + [c], snapshot, find_paths, config)
            if len(trial.unknown_path_ids) > len(current.unknown_path_ids):
                continue   # a fix must not make paths unscorable and call that progress
            gain = current.known_risk - trial.known_risk
            score = gain - constraints.cost_weight * c.cost
            if best is None or score > best[0] + eps:   # ties keep the earlier candidate_id
                best = (score, c, trial)
        if best is None or best[0] <= eps:
            break
        _, pick, current = best
        chosen.append(pick)
        chosen_ids.add(pick.candidate_id)
        total_cost += pick.cost

    assumptions = [
        "Greedy approximation: picks the best marginal fix each round; not guaranteed globally optimal.",
        "Cost and disruption are 0-1 assumptions, not measured values.",
        "Risk is a relative route score, not a probability.",
    ]
    if baseline.unknown_path_ids:
        assumptions.append(
            f"{len(baseline.unknown_path_ids)} path(s) have unknown risk and are excluded from the optimized total."
        )
    if unmet:
        assumptions.append(f"Mandatory edges with no matching candidate: {unmet}")

    return OptimizerResult(
        chosen=tuple(chosen),
        baseline=baseline,
        residual=current,
        total_cost=total_cost,
        rejected=tuple(rejected),
        assumptions=tuple(assumptions),
    )


def recommend_fixes(
    paths,
    assessments,
    snapshot,
    constraints: OptimizerConstraints | None = None,
    *,
    find_paths,
    config: RiskConfig | None = None,
) -> list[RemediationRecommendation]:
    """Choose fixes with the greedy optimizer; return SIMULATED recommendations.

    Each recommendation is that fix simulated alone. The set-level effect
    (combined cost and residual risk) is stated in each one's assumptions.
    """
    mismatched = sorted(a.path_id for a in assessments if a.graph_version != snapshot.version)
    if mismatched:
        raise ValueError(f"assessments were computed on a different graph version: {mismatched}")

    candidates = generate_candidates(paths, snapshot)
    result = greedy_select(candidates, snapshot, find_paths, constraints, config)

    n = len(result.chosen)
    summary = (
        f"Whole chosen set: total cost {result.total_cost:.2f} (0-1 assumption); "
        f"known relative risk {result.baseline.known_risk:.2f} -> {result.residual.known_risk:.2f}; "
        f"{len(result.residual.residual_path_ids)} path(s) remain."
    )
    overlap = (
        "Blocked/residual paths and risk reduction on this recommendation are for this fix "
        "alone; they overlap when fixes share paths."
    )

    out: list[RemediationRecommendation] = []
    for i, cand in enumerate(result.chosen, start=1):
        rec = recommend(cand, snapshot, find_paths, config)
        notes = [f"Fix {i} of {n} chosen by the greedy optimizer.", summary, overlap, *result.assumptions]
        merged = list(rec.assumptions) + [x for x in notes if x not in rec.assumptions]
        out.append(rec.model_copy(update={"assumptions": merged}))
    return out