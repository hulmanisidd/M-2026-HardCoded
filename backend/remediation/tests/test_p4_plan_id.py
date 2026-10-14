from backend.remediation.candidates import generate_candidates
from backend.remediation.optimizer import recommend_fixes
from backend.remediation.scoring import rank_paths
from backend.remediation.tests.p4_helpers import build, find_paths


def test_recommendation_carries_its_plan_id():
    snap = build()
    paths = find_paths(snap)
    plan_ids = {c.plan.id for c in generate_candidates(paths, snap)}
    recs = recommend_fixes(paths, rank_paths(paths, snap), snap, find_paths=find_paths)
    assert recs
    for r in recs:
        assert r.plan_id is not None
        assert r.plan_id in plan_ids