from contracts import RiskAssessment

from backend.remediation.candidates import generate_candidates
from backend.remediation.explanations import explain_assessment, explain_fix_set
from backend.remediation.optimizer import greedy_select
from backend.remediation.tests.p4_helpers import build, find_paths

def test_scored_assessment_shows_formula_and_factors():
    a = RiskAssessment(
        path_id="p1", graph_version="v1",
        likelihood_score=0.7, impact_score=0.8, confidence="high", risk_score=0.56,
        reasons=["target b2 criticality=high -> impact 0.8", "3 hop(s) -> length factor 0.70"],
        unknowns=[],
    )
    out = explain_assessment(a)
    assert "Risk: 0.56 = likelihood 0.70 x impact 0.80" in out
    assert "not a probability" in out
    assert "3 hop(s) -> length factor 0.70" in out
    assert "Unknowns:" not in out


def test_unknown_assessment_is_reported_not_scored():
    a = RiskAssessment(
        path_id="p2", graph_version="v1",
        likelihood_score=None, impact_score=0.8, confidence="unknown", risk_score=None,
        reasons=["target b2 criticality=high -> impact 0.8"],
        unknowns=["edge e1 has UNKNOWN status"],
    )
    out = explain_assessment(a)
    assert "UNKNOWN" in out
    assert "edge e1 has UNKNOWN status" in out
    assert "Risk: 0" not in out

def test_fix_set_explanation_states_totals_assumptions_and_shared_cause():
    snap = build()
    paths = find_paths(snap)
    result = greedy_select(list(generate_candidates(paths, snap)), snap, find_paths)
    out = explain_fix_set(result)
    assert "Known risk: 2.11 ->" in out
    assert "not probabilities" in out
    assert "shared root cause" in out
    assert "not guaranteed globally optimal" in out
    assert "Paths still present after fixes: 0" in out

def test_explain_recommendation_describes_fraction_and_unknowns():
    from contracts import RemediationRecommendation
    from backend.remediation.explanations import explain_recommendation

    full = RemediationRecommendation(
        recommendation_id="rec_test",
        graph_version="v1",
        action_type="restrict_role_trust",
        target_id="u",
        estimated_cost=0.3,
        expected_blocked_path_ids=["p1", "p2"],
        residual_path_ids=["p3"],
        estimated_risk_reduction=0.6,
        assumptions=["example assumption"],
        verification_status="SIMULATED",
    )
    text = explain_recommendation(full)
    lines = text.splitlines()

    assert "rec_test" in lines[0] and "[SIMULATED]" in lines[0]
    assert "Action: restrict_role_trust on u" in text
    assert "Estimated cost: 0.30" in text
    assert "blocks 2 path(s), 1 path(s) remain" in text
    reduction_line = next(l for l in lines if l.startswith("Estimated risk reduction"))
    assert "0.60" in reduction_line
    assert "fraction of known baseline route risk blocked" in reduction_line
    assert "relative route score" not in reduction_line
    assert "  - example assumption" in lines

    empty = RemediationRecommendation(
        recommendation_id="rec_empty",
        graph_version="v1",
        action_type="remove_read_permission",
        target_id="r3",
    )
    empty_text = explain_recommendation(empty)
    assert "Estimated cost: n/a" in empty_text
    assert "Estimated risk reduction: n/a" in empty_text
    assert "Assumptions:" not in empty_text