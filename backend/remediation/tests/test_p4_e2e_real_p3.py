from functools import partial

from backend.paths.engine import find_paths
from backend.remediation.optimizer import recommend_fixes
from backend.remediation.scoring import rank_paths
from backend.remediation.tests.p4_helpers import build

ENTRIES = ("u",)
TARGETS = ("b", "b2")


def test_p4_on_top_of_real_p3():
    snap = build()
    finder = partial(find_paths, entry_points=ENTRIES, targets=TARGETS)

    paths = finder(snap)
    # Hand-derived from build(): u>r1>r2>b, u>r1>r2>b2, u>r3>b
    assert len(paths) == 3
    ids = {p.path_id for p in paths}

    assessments = rank_paths(paths, snap)
    recs = recommend_fixes(paths, assessments, snap, find_paths=finder)

    assert recs, "expected at least one recommendation"
    for rec in recs:
        assert rec.verification_status == "SIMULATED"  # P4 never claims more
        assert rec.graph_version == snap.version
        blocked, residual = set(rec.expected_blocked_path_ids), set(rec.residual_path_ids)
        assert blocked and blocked <= ids
        assert blocked.isdisjoint(residual)
        assert blocked | residual == ids
        # No single edge lies on all 3 paths, so every single fix leaves an alternate route.
        assert residual