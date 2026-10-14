from functools import partial

from backend.paths.engine import find_paths
from backend.remediation.optimizer import recommend_fixes
from backend.remediation.scoring import rank_paths
from backend.remediation.tests.p4_helpers import build
from contracts import PathOptions


def test_capped_search_does_not_crash_and_is_flagged():
    snap = build()
    finder = partial(find_paths, entry_points=("u",), targets=("b", "b2"),
                     options=PathOptions(max_paths=2))
    paths = finder(snap)
    recs = recommend_fixes(paths, rank_paths(paths, snap), snap, find_paths=finder)
    notes = [a for r in recs for a in r.assumptions]
    assert any("truncated" in a for a in notes)