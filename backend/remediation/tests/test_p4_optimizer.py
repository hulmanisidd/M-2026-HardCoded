from backend.remediation.candidates import generate_candidates
from backend.remediation.optimizer import OptimizerConstraints, greedy_select, residual_risk
from backend.remediation.tests.p4_helpers import build, cand_for, find_paths
import pytest

from backend.remediation.optimizer import recommend_fixes
from backend.remediation.scoring import rank_paths
from contracts.risk import RiskAssessment
from datetime import datetime, timezone
from backend.remediation.simulation import recommend
from contracts import EdgeStatus, Entity, GraphSnapshot, NodeType, RelationType, Relationship, Criticality
from backend.remediation.tests.p4_helpers import NOW
def test_no_fixes_leaves_all_three_paths():
    s = build()
    r = residual_risk([], s, find_paths)
    assert len(r.residual_path_ids) == 3
    assert r.known_risk > 0
    assert r.unknown_path_ids == ()


def test_single_fix_leaves_alternate_routes_and_lowers_risk():
    s = build()
    base = residual_risk([], s, find_paths)
    after = residual_risk([cand_for(s, "r2", "b")], s, find_paths)
    assert len(after.residual_path_ids) == 2     # u-r1-r2-b2 and u-r3-b survive
    assert after.known_risk < base.known_risk
    assert after.unknown_path_ids == ()

def test_fixes_are_applied_together_not_one_by_one():
    s = build()
    chosen = [cand_for(s, "r1", "r2"), cand_for(s, "r3", "b")]
    r = residual_risk(chosen, s, find_paths)
    assert r.residual_path_ids == ()
    assert r.known_risk == 0.0
    assert r.unknown_path_ids == ()

def run(constraints=None):
    s = build()
    return s, greedy_select(generate_candidates(find_paths(s), s), s, find_paths, constraints)


def test_unconstrained_blocks_every_path():
    s, r = run()
    assert r.baseline.known_risk > 0
    assert r.residual.residual_path_ids == ()
    assert r.residual.known_risk == 0.0
    assert r.residual.unknown_path_ids == ()
    assert len(r.chosen) >= 2          # no single fix blocks all three paths


def test_forbidden_edge_is_never_chosen():
    s = build()
    banned = cand_for(s, "r1", "r2")
    cons = OptimizerConstraints(forbidden_edge_ids=frozenset(banned.plan.removed_edge_ids))
    r = greedy_select(generate_candidates(find_paths(s), s), s, find_paths, cons)
    chosen_edges = {e for c in r.chosen for e in c.plan.removed_edge_ids}
    assert not chosen_edges & set(banned.plan.removed_edge_ids)
    assert banned.candidate_id in [cid for cid, _ in r.rejected]


def test_forbidding_an_action_type_forces_different_fixes():
    s = build()
    cons = OptimizerConstraints(forbidden_action_types=frozenset({"restrict_role_trust"}))
    r = greedy_select(generate_candidates(find_paths(s), s), s, find_paths, cons)
    assert {c.action_type for c in r.chosen} == {"remove_read_permission"}
    assert len(r.chosen) == 3          # one read fix per path, since the shared trust edges are ruled out
    assert r.residual.residual_path_ids == ()


def test_result_states_assumptions_and_no_global_optimality_claim():
    s, r = run()
    text = " ".join(r.assumptions).lower()
    assert "greedy" in text
    assert "not guaranteed globally optimal" in text
    assert "0-1 assumptions" in text


def test_budget_cap_limits_total_cost_and_leaves_residual_risk():
    s = build()
    cands = generate_candidates(find_paths(s), s)
    cons = OptimizerConstraints(max_total_cost=0.25)
    r = greedy_select(cands, s, find_paths, cons)
    assert r.total_cost <= 0.25
    assert r.residual.known_risk > 0          # budget too small to block everything


def test_disruption_cap_rules_out_fixes_above_it():
    s = build()
    cands = generate_candidates(find_paths(s), s)
    cons = OptimizerConstraints(max_disruption_per_action=0.45)
    r = greedy_select(cands, s, find_paths, cons)
    assert all(c.disruption <= 0.45 for c in r.chosen)
    assert any(c.disruption > 0.45 for c in cands)       # the cap really excluded something
    assert {cid for cid, _ in r.rejected} == {c.candidate_id for c in cands if c.disruption > 0.45}


def test_max_actions_caps_number_of_fixes():
    s = build()
    r = greedy_select(generate_candidates(find_paths(s), s), s, find_paths,
                      OptimizerConstraints(max_actions=1))
    assert len(r.chosen) == 1


def test_mandatory_fix_is_included():
    s = build()
    must = cand_for(s, "u", "r3")
    cons = OptimizerConstraints(mandatory_edge_ids=frozenset(must.plan.removed_edge_ids))
    r = greedy_select(generate_candidates(find_paths(s), s), s, find_paths, cons)
    assert must.candidate_id in [c.candidate_id for c in r.chosen]
def recs(constraints=None):
    s = build()
    p = find_paths(s)
    return s, recommend_fixes(p, rank_paths(p, s), s, constraints, find_paths=find_paths)


def test_recommend_fixes_returns_simulated_recommendations_with_cost():
    s, r = recs()
    assert len(r) >= 2
    assert all(x.verification_status == "SIMULATED" for x in r)
    assert all(x.estimated_cost is not None for x in r)
    assert all(x.graph_version == s.version for x in r)


def test_recommendations_state_greedy_and_cost_assumptions():
    _, r = recs()
    for x in r:
        text = " ".join(x.assumptions).lower()
        assert "not guaranteed globally optimal" in text
        assert "0-1 assumption" in text


def test_recommend_fixes_respects_forbidden_action_type():
    _, r = recs(OptimizerConstraints(forbidden_action_types=frozenset({"restrict_role_trust"})))
    assert len(r) == 3
    assert {x.action_type for x in r} == {"remove_read_permission"}


def test_assessments_from_another_graph_version_are_rejected():
    s = build()
    p = find_paths(s)
    stale = [RiskAssessment(path_id="x", graph_version="v0", impact_score=0.5, confidence="low")]
    with pytest.raises(ValueError):
        recommend_fixes(p, stale, s, find_paths=find_paths)

def build_with_unknown_edge():
    """Same shape as build(), but the u->r3 edge is UNKNOWN, so path u-r3-b has unknown risk."""
    s = build()
    edges = tuple(
        e.model_copy(update={"status": EdgeStatus.UNKNOWN})
        if (e.source_id, e.target_id) == ("u", "r3") else e
        for e in s.edges
    )
    return GraphSnapshot(version=s.version, created_at=NOW, entities=s.entities, edges=edges)


def test_unknown_path_is_reported_not_counted_as_zero_risk():
    s = build_with_unknown_edge()
    base = residual_risk([], s, find_paths)
    assert len(base.unknown_path_ids) == 1
    assert len(base.residual_path_ids) == 3          # the unknown path is still present, never dropped
    assert base.known_risk > 0                       # the other two paths are scored


def test_optimizer_states_unknown_paths_are_excluded_from_totals():
    s = build_with_unknown_edge()
    r = greedy_select(generate_candidates(find_paths(s), s), s, find_paths)
    text = " ".join(r.assumptions).lower()
    assert "unknown risk" in text
    assert "excluded" in text


def test_fix_on_unknown_path_is_not_credited_with_risk_reduction():
    s = build_with_unknown_edge()
    p = find_paths(s)
    a = rank_paths(p, s)
    unknown_ids = {x.path_id for x in a if x.risk_score is None}
    known = {x.path_id: x.risk_score for x in a if x.risk_score is not None}
    assert len(unknown_ids) == 1 and len(known) == 2

    recs = recommend_fixes(p, a, s, find_paths=find_paths)
    assert len(recs) == 1, "only the fix on known-risk paths should be chosen"
    r = recs[0]

    # the unknown path is never listed as blocked-and-credited, and stays residual
    assert not (unknown_ids & set(r.expected_blocked_path_ids))
    assert unknown_ids <= set(r.residual_path_ids)

    # reduction is exactly blocked known risk / known total
    expected = sum(known[i] for i in r.expected_blocked_path_ids) / sum(known.values())
    assert r.estimated_risk_reduction == pytest.approx(expected)
    assert r.estimated_risk_reduction == pytest.approx(1.0)

    # the exclusion is stated on the recommendation itself
    assert any("excluded from risk_reduction" in t for t in r.assumptions)

def test_fix_blocking_only_unknown_path_gets_zero_reduction_not_credit():
    s = build_with_unknown_edge()
    r = recommend(cand_for(s, "u", "r3"), s, find_paths)
    assert len(r.expected_blocked_path_ids) == 1
    assert len(r.residual_path_ids) == 2
    assert r.estimated_risk_reduction == pytest.approx(0.0)
    assert r.estimated_risk_reduction is not None
    assert any("excluded from risk_reduction" in t for t in r.assumptions)