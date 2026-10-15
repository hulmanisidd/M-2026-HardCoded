from functools import partial

from backend.paths.engine import find_paths
from backend.remediation.scoring import rank_paths
from backend.remediation.simulation import simulate_plan
from backend.rerouting.config import ReroutingPolicy
from backend.rerouting.discovery import build_explicit_path
from backend.rerouting.models import AccessRequirement, CheckName as C, Evidence, Verdict as V
from backend.rerouting.validators import (
    ConditionDecision, ValidationContext, assess_candidate,
)
from contracts.remediation import RemediationPlan
from tests.unit.rerouting_graphs import A, build, eid

ATTACKER_TO_BACKUP = [("attacker", A, "backup")]


def make_ctx(g, remove=(("ops", "bucket"),), req=None, complete=True, evaluator=None,
             policy=None, trusted=()):
    req = req or AccessRequirement(principal_id="dev", resource_id="bucket", trusted_entry_ids=trusted)
    finder = partial(find_paths, entry_points=("dev", "attacker"), targets=("bucket",))
    removed = tuple(eid(g, s, t) for s, t in remove)
    _, residual = simulate_plan(g, RemediationPlan(id="sw", base_version=g.version,
                                                   removed_edge_ids=removed), finder)
    post = g.fork(removed)
    unknown = frozenset(a.path_id for a in rank_paths(residual, post) if a.risk_score is None)
    return ValidationContext(pre=g, post=post, removed_edge_ids=frozenset(removed), requirement=req,
                             policy=policy or ReroutingPolicy(), residual_attack_paths=tuple(residual),
                             unknown_residual_ids=unknown, attack_search_complete=complete,
                             condition_evaluator=evaluator)


def route(g, *hops, req=None):
    req = req or AccessRequirement(principal_id="dev", resource_id="bucket")
    p, why = build_explicit_path(g, req, tuple(eid(g, s, t) for s, t in hops))
    assert p, why
    return p


BACKUP = (("dev", "backup"), ("backup", "bucket"))
PRIMARY = (("dev", "ops"), ("ops", "bucket"))


def test_valid_backup_passes_every_check():
    g = build()
    a = assess_candidate(route(g, *BACKUP), make_ctx(g))
    assert a.verdict is V.VERIFIED, a.blockers
    assert all(r.evidence for r in a.checks.values())


def test_primary_is_unavailable_when_plan_removes_its_edge():
    g = build()
    a = assess_candidate(route(g, *PRIMARY), make_ctx(g))
    assert a.verdict_for(C.AVAILABILITY) is V.REJECTED and a.verdict is V.REJECTED
    assert a.verdict_for(C.LEGITIMATE_ACCESS_PRESERVED) is V.REJECTED


def test_known_outage_makes_route_unavailable():
    g = build()
    req = AccessRequirement(principal_id="dev", resource_id="bucket",
                            unavailable_edge_ids=(eid(g, "backup", "bucket"),))
    a = assess_candidate(route(g, *BACKUP), make_ctx(g, req=req))
    assert a.verdict_for(C.AVAILABILITY) is V.REJECTED


def test_backup_sharing_edge_with_untrusted_attack_path_is_rejected():
    g = build(extra=ATTACKER_TO_BACKUP)
    a = assess_candidate(route(g, *BACKUP), make_ctx(g))
    assert a.verdict_for(C.NO_ATTACK_PATH_REINTRODUCED) is V.REJECTED
    assert a.verdict is V.REJECTED


def test_same_route_is_fine_when_the_other_entry_is_explicitly_trusted():
    g = build(extra=ATTACKER_TO_BACKUP)
    a = assess_candidate(route(g, *BACKUP), make_ctx(g, trusted=("attacker",)))
    assert a.verdict is V.VERIFIED, a.blockers


def test_unscorable_overlapping_attack_path_is_unknown_not_safe():
    g = build(extra=ATTACKER_TO_BACKUP, statuses={"attacker>backup": "unknown"})
    a = assess_candidate(route(g, *BACKUP), make_ctx(g))
    assert a.verdict_for(C.NO_ATTACK_PATH_REINTRODUCED) is V.UNKNOWN
    assert a.verdict is not V.VERIFIED


def test_incomplete_attack_search_is_unknown():
    g = build()
    a = assess_candidate(route(g, *BACKUP), make_ctx(g, complete=False))
    assert a.verdict_for(C.NO_ATTACK_PATH_REINTRODUCED) is V.UNKNOWN


def test_privilege_escalation_route_is_rejected_by_policy():
    g = build()
    a = assess_candidate(route(g, ("dev", "escalator"), ("escalator", "bucket")), make_ctx(g))
    assert a.verdict_for(C.POLICY_CONSTRAINTS) is V.REJECTED and a.verdict is V.REJECTED


def test_missing_evidence_is_unknown():
    g = build(no_evidence={"backup>bucket"})
    a = assess_candidate(route(g, *BACKUP), make_ctx(g))
    assert a.verdict_for(C.PERMISSION_GRANTED) is V.UNKNOWN and a.verdict is V.UNKNOWN
    assert "no evidence_ids" in a.checks[C.PERMISSION_GRANTED].reason


def test_evidence_requirement_can_be_relaxed_explicitly():
    g = build(no_evidence={"backup>bucket"})
    ctx = make_ctx(g, policy=ReroutingPolicy(require_evidence=False))
    r = assess_candidate(route(g, *BACKUP), ctx).checks[C.PERMISSION_GRANTED]
    # relaxed on purpose: other edges still supply evidence for the check
    assert r.verdict is V.VERIFIED and r.evidence


def test_weak_edge_statuses_are_unknown_and_invalidated_is_rejected():
    for status in ("stale", "inferred", "unknown"):
        g = build(statuses={"dev>backup": status})
        assert assess_candidate(route(g, *BACKUP), make_ctx(g)).verdict_for(C.PERMISSION_GRANTED) is V.UNKNOWN
    g = build(statuses={"dev>backup": "invalidated"})
    assert assess_candidate(route(g, *BACKUP), make_ctx(g)).verdict_for(C.PERMISSION_GRANTED) is V.REJECTED


def test_conditions_unknown_without_evaluator():
    g = build(conditions={"backup>bucket": {"aws:SourceIp": "10.0.0.0/8"}})
    a = assess_candidate(route(g, *BACKUP), make_ctx(g))
    assert a.verdict_for(C.POLICY_CONSTRAINTS) is V.UNKNOWN and a.verdict is V.UNKNOWN


def test_conditions_with_evaluator_outcomes():
    g = build(conditions={"backup>bucket": {"k": "v"}})
    ev = (Evidence(source="iam_policy_simulator", detail="allowed", reference="sim-1"),)
    ok = lambda e: ConditionDecision(V.VERIFIED, "allowed", ev)
    no = lambda e: ConditionDecision(V.REJECTED, "denied by SCP")
    bare = lambda e: ConditionDecision(V.VERIFIED, "trust me")            # no evidence
    unsure = lambda e: ConditionDecision(V.UNKNOWN, "simulator error", ev)
    pol = lambda ev_fn: assess_candidate(route(g, *BACKUP), make_ctx(g, evaluator=ev_fn)).verdict_for(C.POLICY_CONSTRAINTS)
    assert pol(ok) is V.VERIFIED and pol(no) is V.REJECTED
    assert pol(bare) is V.UNKNOWN and pol(unsure) is V.UNKNOWN


def test_stale_path_from_another_graph_version_is_unknown():
    g1, g2 = build(version="v1"), build(version="v2")
    p = route(g1, *BACKUP)
    a = assess_candidate(p, make_ctx(g2))
    assert a.verdict_for(C.GRAPH_CONNECTED) is V.UNKNOWN and a.verdict is not V.VERIFIED