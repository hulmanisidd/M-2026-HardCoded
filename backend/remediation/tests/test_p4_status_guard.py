from backend.remediation.optimizer import recommend_fixes
from backend.remediation.scoring import rank_paths
from backend.remediation.tests.p4_helpers import build, find_paths


def test_p4_only_emits_proposed_or_simulated():
    snap = build()
    paths = find_paths(snap)
    recs = recommend_fixes(paths, rank_paths(paths, snap), snap, find_paths=find_paths)
    assert recs
    # VERIFIED / APPLIED / APPROVED / PARTIALLY_VERIFIED belong to P5.
    assert {r.verification_status for r in recs} <= {"PROPOSED", "SIMULATED"}