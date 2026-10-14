from contracts import RiskAssessment

from backend.remediation.candidates import generate_candidates
from backend.remediation.explanations import explain_assessment, explain_fix_set
from backend.remediation.optimizer import greedy_select
from test_p4_simulation import build, find_paths

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