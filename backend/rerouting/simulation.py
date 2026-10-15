"""Switch simulation. Built ON TOP of P4: simulate_plan gives the residual
attack paths, residual_risk gives the before/after risk numbers. Nothing here
re-implements residual-path detection or the optimizer, and nothing touches AWS.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from backend.remediation.candidates import Candidate
from backend.remediation.optimizer import ResidualRisk, residual_risk
from backend.remediation.scoring import RiskConfig
from backend.remediation.simulation import PathFinder, simulate_plan
from contracts.graph import GraphSnapshot
from contracts.paths import AttackPath
from contracts.remediation import RemediationPlan

from .config import ReroutingPolicy
from .models import AccessPath, AccessRequirement, CheckName, Evidence, SwitchSimulation, Verdict
from .validators import (
    ConditionEvaluator, ValidationContext, check_access_preserved, check_availability,
)


@dataclass(frozen=True)
class ResidualView:
    """The world after the remediation, as P4 sees it."""
    plan: RemediationPlan
    post: GraphSnapshot
    residual_paths: tuple[AttackPath, ...]
    before: ResidualRisk
    after: ResidualRisk


def _plan_id(snapshot: GraphSnapshot, edge_ids: Iterable[str]) -> str:
    key = snapshot.version + "|" + ",".join(sorted(edge_ids))
    return "reroute_" + hashlib.sha256(key.encode()).hexdigest()[:12]


def build_residual_view(
    snapshot: GraphSnapshot, removed_edge_ids: Iterable[str], find_attack_paths: PathFinder,
    risk_config: RiskConfig | None = None,
) -> ResidualView:
    removed = tuple(sorted(set(removed_edge_ids)))
    if not removed:
        raise ValueError("nothing to simulate: no edges are removed or unavailable")
    plan = RemediationPlan(id=_plan_id(snapshot, removed), base_version=snapshot.version,
                           removed_edge_ids=removed, rationale="rerouting what-if")
    _, residual = simulate_plan(snapshot, plan, find_attack_paths)          # P4
    stand_in = Candidate(candidate_id=plan.id, action_type="reroute_what_if", target_id="n/a",
                         plan=plan, cost=0.0, disruption=0.0, covered_path_ids=(),
                         rationale=plan.rationale)
    return ResidualView(
        plan=plan, post=snapshot.fork(removed), residual_paths=tuple(residual),
        before=residual_risk([], snapshot, find_attack_paths, risk_config),  # P4
        after=residual_risk([stand_in], snapshot, find_attack_paths, risk_config),  # P4
    )


def make_context(
    snapshot: GraphSnapshot, view: ResidualView, requirement: AccessRequirement,
    policy: ReroutingPolicy, *, plan_edge_ids: Iterable[str], attack_search_complete: bool,
    condition_evaluator: ConditionEvaluator | None = None,
) -> ValidationContext:
    return ValidationContext(
        pre=snapshot, post=view.post, removed_edge_ids=frozenset(plan_edge_ids),
        requirement=requirement, policy=policy, residual_attack_paths=view.residual_paths,
        unknown_residual_ids=frozenset(view.after.unknown_path_ids),
        attack_search_complete=attack_search_complete, condition_evaluator=condition_evaluator,
    )


def simulate_switch(view: ResidualView, ctx: ValidationContext, backup: AccessPath) -> SwitchSimulation:
    preserved = (
        check_access_preserved(backup, ctx).verdict is Verdict.VERIFIED
        and check_availability(backup, ctx).verdict is Verdict.VERIFIED
    )
    mine = set(backup.edge_ids)
    trusted = ctx.requirement.trusted_entries
    exposed = tuple(sorted(
        p.path_id for p in view.residual_paths
        if p.entry_node_id not in trusted and mine & set(p.edge_ids)
    ))
    return SwitchSimulation(
        backup_path_id=backup.path_id, plan_id=view.plan.id, access_preserved=preserved,
        residual_before=view.before.residual_path_ids, residual_after=view.after.residual_path_ids,
        unknown_before=view.before.unknown_path_ids, unknown_after=view.after.unknown_path_ids,
        known_risk_before=view.before.known_risk, known_risk_after=view.after.known_risk,
        exposed_attack_path_ids=exposed,
        evidence=(Evidence(source="p4_simulate_plan",
                           detail=f"edge removal on a graph copy; {len(view.residual_paths)} residual path(s)",
                           reference=view.post.version),),
    )
