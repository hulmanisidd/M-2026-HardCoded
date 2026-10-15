"""Fail-closed validators. One function per required check.

Verdict rules: VERIFIED needs positive evidence; anything missing, weak
(stale/inferred/unknown edge, no evidence id, unevaluated condition) is
UNKNOWN; a definite violation is REJECTED. Only all-VERIFIED is usable.

Reuses P3's validate_path / check_transition and P4's simulate_plan output
(passed in via ValidationContext); it does not re-implement either.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from backend.paths.validator import validate_path
from contracts.graph import GraphSnapshot, TransitionResult
from contracts.paths import AttackPath, Feasibility
from contracts.relationships import Relationship

from .config import ReroutingPolicy
from .models import (
    AccessPath, AccessRequirement, CandidateAssessment, CheckName, CheckResult,
    Evidence, Verdict,
)

COND_REASON = "conditions_require_evaluation"


@dataclass(frozen=True)
class ConditionDecision:
    verdict: Verdict
    reason: str
    evidence: tuple[Evidence, ...] = ()


# Optional port: evaluate an edge's IAM conditions (e.g. via the IAM policy
# simulator). Without it every conditional edge stays UNKNOWN.
ConditionEvaluator = Callable[[Relationship], ConditionDecision]


@dataclass(frozen=True)
class ValidationContext:
    pre: GraphSnapshot                      # graph before the remediation
    post: GraphSnapshot                     # forked copy after the remediation
    removed_edge_ids: frozenset[str]
    requirement: AccessRequirement
    policy: ReroutingPolicy
    residual_attack_paths: tuple[AttackPath, ...]   # P4 live residual on `post`
    unknown_residual_ids: frozenset[str]            # subset with unscorable risk
    attack_search_complete: bool                    # caller asserts not truncated
    condition_evaluator: ConditionEvaluator | None = None


def _res(check, verdict, reason, evidence=()):
    return CheckResult(check=check, verdict=verdict, reason=reason, evidence=tuple(evidence))


def _edge_evidence(edge: Relationship, detail: str) -> tuple[Evidence, ...]:
    refs = edge.evidence_ids or (None,)
    return tuple(Evidence(source="graph_edge", detail=f"{edge.edge_id}: {detail}", reference=r)
                 for r in refs)


def check_graph_connected(path: AccessPath, ctx: ValidationContext) -> CheckResult:
    c = CheckName.GRAPH_CONNECTED
    if path.graph_version != ctx.pre.version:
        return _res(c, Verdict.UNKNOWN,
                    f"path is from graph {path.graph_version}, snapshot is {ctx.pre.version}")
    at = path.principal_id
    for eid in path.edge_ids:
        e = ctx.pre.get_edge(eid)
        if e is None:
            return _res(c, Verdict.REJECTED, f"edge {eid} not in graph")
        if e.source_id != at:
            return _res(c, Verdict.REJECTED, f"edge {eid} does not continue from {at}")
        at = e.target_id
    if at != path.resource_id:
        return _res(c, Verdict.REJECTED, f"route ends at {at}, not {path.resource_id}")
    return _res(c, Verdict.VERIFIED, f"{path.hops} contiguous edge(s) exist",
                [Evidence(source="graph_snapshot", detail="every hop exists and chains",
                          reference=ctx.pre.version)])


def check_permission_granted(path: AccessPath, ctx: ValidationContext) -> CheckResult:
    c = CheckName.PERMISSION_GRANTED
    _, results = validate_path(ctx.pre, path.edge_ids, {})
    evidence: list[Evidence] = []
    unknown: list[str] = []
    for eid, r in zip(path.edge_ids, results):
        if r.status is Feasibility.BLOCKED:
            return _res(c, Verdict.REJECTED, f"edge {eid} blocked: {r.reason}")
        if r.status is Feasibility.CONDITIONAL and r.reason != COND_REASON:
            unknown.append(f"edge {eid}: {r.reason}")      # inferred/stale/unknown
            continue
        edge = ctx.pre.get_edge(eid)
        if ctx.policy.require_evidence and not edge.evidence_ids:
            unknown.append(f"edge {eid}: confirmed but no evidence_ids")
            continue
        evidence.extend(_edge_evidence(edge, r.reason))
    if unknown:
        return _res(c, Verdict.UNKNOWN, "; ".join(unknown))
    return _res(c, Verdict.VERIFIED, "every edge confirmed, in window, with evidence", evidence)


def check_policy_constraints(path: AccessPath, ctx: ValidationContext) -> CheckResult:
    c = CheckName.POLICY_CONSTRAINTS
    evidence: list[Evidence] = []
    unknown: list[str] = []
    for eid in path.edge_ids:
        e = ctx.pre.get_edge(eid)
        if e is None:
            return _res(c, Verdict.REJECTED, f"edge {eid} not in graph")
        if str(e.relation_type) not in ctx.policy.legit_relations:
            return _res(c, Verdict.REJECTED,
                        f"edge {eid} uses non-legitimate relation {e.relation_type.value}")
        if e.conditions:
            if ctx.condition_evaluator is None:
                unknown.append(f"edge {eid}: conditions not evaluated")
                continue
            d = ctx.condition_evaluator(e)
            if d.verdict is Verdict.REJECTED:
                return _res(c, Verdict.REJECTED, f"edge {eid}: {d.reason}")
            if d.verdict is not Verdict.VERIFIED or not d.evidence:
                unknown.append(f"edge {eid}: {d.reason}")
                continue
            evidence.extend(d.evidence)
        else:
            evidence.append(Evidence(source="graph_edge", detail=f"{eid}: relation allowed, no conditions",
                                     reference=eid))
    if unknown:
        return _res(c, Verdict.UNKNOWN, "; ".join(unknown))
    return _res(c, Verdict.VERIFIED, "relations allowed; conditions satisfied or absent", evidence)


def check_availability(path: AccessPath, ctx: ValidationContext) -> CheckResult:
    """MODEL availability (edges survive the plan, no known outage); not live health."""
    c = CheckName.AVAILABILITY
    for eid in path.edge_ids:
        if eid in ctx.removed_edge_ids:
            return _res(c, Verdict.REJECTED, f"edge {eid} is removed by the remediation plan")
        if eid in ctx.requirement.unavailable_edge_ids:
            return _res(c, Verdict.REJECTED, f"edge {eid} is reported unavailable")
        if ctx.post.get_edge(eid) is None:
            return _res(c, Verdict.REJECTED, f"edge {eid} absent after the change")
    return _res(c, Verdict.VERIFIED, "all edges present after the change; no known outage",
                [Evidence(source="graph_snapshot", detail="edges present in post-change fork",
                          reference=ctx.post.version)])


def check_no_attack_path_reintroduced(path: AccessPath, ctx: ValidationContext) -> CheckResult:
    c = CheckName.NO_ATTACK_PATH_REINTRODUCED
    if not ctx.attack_search_complete:
        return _res(c, Verdict.UNKNOWN, "attack-path search may be truncated; residual set not proven complete")
    trusted = ctx.requirement.trusted_entries
    mine = set(path.edge_ids)
    overlap = [p for p in ctx.residual_attack_paths
               if p.entry_node_id not in trusted and mine & set(p.edge_ids)]
    if overlap:
        known = [p.path_id for p in overlap if p.path_id not in ctx.unknown_residual_ids]
        if known:
            return _res(c, Verdict.REJECTED,
                        f"backup shares edges with live attack path(s) from untrusted entries: {sorted(known)}")
        return _res(c, Verdict.UNKNOWN,
                    f"backup shares edges with unscorable attack path(s): {sorted(p.path_id for p in overlap)}")
    return _res(c, Verdict.VERIFIED, "no untrusted residual attack path uses any backup edge",
                [Evidence(source="p4_simulation",
                          detail=f"{len(ctx.residual_attack_paths)} residual path(s) checked",
                          reference=ctx.post.version)])


def check_access_preserved(path: AccessPath, ctx: ValidationContext) -> CheckResult:
    """Independently re-walk the route on the POST-change graph via P3's validate_path."""
    c = CheckName.LEGITIMATE_ACCESS_PRESERVED
    status, results = validate_path(ctx.post, path.edge_ids, {})
    for eid, r in zip(path.edge_ids, results):
        if r.status is Feasibility.BLOCKED:
            return _res(c, Verdict.REJECTED, f"after the change edge {eid} is blocked: {r.reason}")
        if r.status is Feasibility.CONDITIONAL and r.reason != COND_REASON:
            return _res(c, Verdict.UNKNOWN, f"after the change edge {eid}: {r.reason}")
    return _res(c, Verdict.VERIFIED,
                f"{ctx.requirement.principal_id} still reaches {ctx.requirement.resource_id} after the change",
                [Evidence(source="p3_validate_path", detail=f"status={status.value}", reference=ctx.post.version)])


ALL_CHECKS = (
    check_graph_connected, check_permission_granted, check_policy_constraints,
    check_availability, check_no_attack_path_reintroduced, check_access_preserved,
)


def assess_candidate(path: AccessPath, ctx: ValidationContext) -> CandidateAssessment:
    results = {}
    for fn in ALL_CHECKS:
        r = fn(path, ctx)
        results[r.check] = r
    return CandidateAssessment(path=path, checks=results)
