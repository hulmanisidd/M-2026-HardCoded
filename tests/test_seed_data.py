"""Checks the hand-written fixture against an independent DFS over check_transition."""
from backend.graph.seed_data import (
    ENTRY_KEYS, TARGET_KEYS, EXPECTED_BLOCKED_COUNT, EXPECTED_NON_BLOCKED_COUNT,
    build_seed, to_snapshot,
)
from contracts import make_path_id


def _enumerate(snap, seed, max_depth=5):
    targets = {seed.entity_ids[k] for k in TARGET_KEYS}
    found = {}

    def dfs(node, seen, edges):
        if len(edges) >= max_depth:
            return
        for e in snap.get_neighbors(node):
            if e.target_id in seen:
                continue
            path = edges + [e.edge_id]
            if e.target_id in targets:
                sts = [snap.check_transition(i, {}).status.value for i in path]
                st = ("blocked" if "blocked" in sts else
                      "conditional" if "conditional" in sts else "feasible_under_model")
                found[make_path_id(tuple(path))] = st
            else:
                dfs(e.target_id, seen | {e.target_id}, path)

    for k in ENTRY_KEYS:
        n = seed.entity_ids[k]
        dfs(n, {n}, [])
    return found


def test_fixture_matches_graph():
    seed = build_seed()
    assert _enumerate(to_snapshot(seed), seed) == seed.expected_paths()


def test_counts_and_stale_unknown_never_feasible():
    seed = build_seed()
    exp = seed.expected_paths()
    assert sum(v == "blocked" for v in exp.values()) == EXPECTED_BLOCKED_COUNT
    assert sum(v != "blocked" for v in exp.values()) == EXPECTED_NON_BLOCKED_COUNT
    snap = to_snapshot(seed)
    for key in ("E2", "E10", "E9"):
        assert snap.check_transition(seed.edge_ids[key], {}).status.value == "conditional"
    assert snap.check_transition(seed.edge_ids["E11"], {}).reason == "edge_expired"