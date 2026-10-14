from backend.remediation.candidates import generate_candidates
from backend.remediation.optimizer import OptimizerConstraints, greedy_select, residual_risk
from test_p4_simulation import build, cand_for, find_paths


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