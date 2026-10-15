"""Public entry point: reroute(...). SIMULATION AND RECOMMENDATION ONLY.

Implemented: route discovery, fail-closed validation, switch simulation, ranking, report.
NOT implemented (on purpose): any change to real AWS permissions or routing.
"""
from __future__ import annotations

from collections.abc import Iterable

from backend.remediation.candidates import Candidate
from backend.remediation.scoring import RiskConfig
from backend.remediation.simulation import PathFinder
from contracts.graph import GraphSnapshot

from .config import ReroutingPolicy
from .discovery import build_explicit_path, discover_access_paths
from .models import AccessRequirement, CandidateAssessment, Outcome, ReroutingReport, Verdict
from .selector import pick_primary, rank_backups
from .simulation import build_residual_view, make_context, simulate_switch
from .validators import ConditionEvaluator, assess_candidate

BASE_NOTES = (
    "simulation/recommendation only: no AWS permission or route was changed",
    "availability is modeled from the graph and reported outages, not live health",
    "simulation = edge removal on a graph copy; real AWS policy semantics are not re-evaluated",
)


def removed_edge_ids_of(candidates: Iterable[Candidate]) -> tuple[str, ...]:
    """Pipeline helper: edges removed by P4's chosen fixes (OptimizerResult.chosen)."""
    return tuple(sorted({e for c in candidates for e in c.plan.removed_edge_ids}))


def reroute(
    snapshot: GraphSnapshot,
    requirement: AccessRequirement,
    removed_edge_ids: Iterable[str],
    *,
    find_attack_paths: PathFinder,
    attack_search_complete: bool,
    policy: ReroutingPolicy | None = None,
    condition_evaluator: ConditionEvaluator | None = None,
    risk_config: RiskConfig | None = None,
) -> ReroutingReport:
    """`attack_search_complete` has no default: the caller must state whether the attack-path
    search behind `find_attack_paths` was NOT truncated (P4 cannot detect this itself)."""
    policy = policy or ReroutingPolicy()
    plan_edges = tuple(sorted(set(removed_edge_ids)))
    down = tuple(sorted(e for e in requirement.unavailable_edge_ids
                        if snapshot.get_edge(e) is not None and e not in plan_edges))
    notes = list(BASE_NOTES)
    ghost = sorted(set(requirement.unavailable_edge_ids) - {e.edge_id for e in snapshot.edges})
    if ghost:
        notes.append(f"unavailable edge ids not in the graph were ignored: {ghost}")

    discovery = discover_access_paths(snapshot, requirement, policy)
    view = build_residual_view(snapshot, plan_edges + down, find_attack_paths, risk_config)
    ctx = make_context(snapshot, view, requirement, policy, plan_edge_ids=plan_edges,
                       attack_search_complete=attack_search_complete,
                       condition_evaluator=condition_evaluator)
    if not discovery.complete:
        notes.append(f"route search incomplete (truncated={discovery.truncated}, "
                     f"unknown endpoints={list(discovery.unknown_endpoints)}): "
                     "absence of a route is NOT proven")

    def report(outcome, **kw) -> ReroutingReport:
        return ReroutingReport(requirement=requirement, graph_version=snapshot.version,
                               outcome=outcome, search_truncated=not discovery.complete,
                               notes=tuple(notes), **kw)

    # 1. primary
    if requirement.primary_edge_ids:
        primary, why = build_explicit_path(snapshot, requirement, requirement.primary_edge_ids)
        if primary is None:
            notes.append(f"supplied primary route is invalid: {why}")
    else:
        primary = pick_primary(discovery.paths, ctx)
        if primary is None:
            notes.append("no route is verified today, so no primary can be identified")
        else:
            notes.append("primary assumed (no usage data): the verified route this change breaks or exposes, else the shortest; pass primary_edge_ids if known")
    if primary is None:
        return report(Outcome.PRIMARY_UNVERIFIABLE)

    # 2. does the primary survive the change and stay safe?
    primary_assessment = assess_candidate(primary, ctx)
    if primary_assessment.verdict is Verdict.VERIFIED:
        notes.append("primary passes every check after the change: no rerouting needed")
        return report(Outcome.PRIMARY_STILL_VALID, primary=primary,
                      assessments=(primary_assessment,))
    notes.append("primary unusable after the change: " + "; ".join(primary_assessment.blockers))

    # 3. validate every other candidate (fail-closed), rank the fully verified ones
    assessed: list[CandidateAssessment] = [
        assess_candidate(p, ctx) for p in discovery.paths if p.path_id != primary.path_id
    ]
    everything = (primary_assessment, *assessed)
    by_id = {a.path.path_id: a for a in assessed}

    # 4. simulate the switch for each verified candidate; first fully safe one wins
    for backup in rank_backups(assessed):
        sim = simulate_switch(view, ctx, backup)
        if sim.is_safe:
            notes.append(f"backup {backup.path_id} verified and its switch simulated safely")
            return report(Outcome.BACKUP_RECOMMENDED, primary=primary, selected_backup=backup,
                          assessments=everything, simulation=sim)
        notes.append(f"candidate {backup.path_id} verified but its simulated switch is unsafe "
                     f"(exposed={list(sim.exposed_attack_path_ids)}, "
                     f"new={list(sim.new_attack_path_ids)}, preserved={sim.access_preserved})")

    # 5. honest failure
    notes.append(f"{len(assessed)} alternative route(s) examined; none passed every check")
    for pid, a in sorted(by_id.items()):
        notes.append(f"rejected {pid}: " + "; ".join(a.blockers))
    return report(Outcome.NO_VALID_BACKUP, primary=primary, assessments=everything)
