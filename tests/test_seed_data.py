"""Seed data: the hand-written EXPECTED_PATHS fixture vs the real graph.

Independent of the path finder: edge-level results come from
GraphSnapshot.check_transition, and path-level status is combined with the
rule written in seed_data.py.
"""
from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.seed_data import (
    ENTRY_KEYS,
    EXPECTED_BLOCKED_COUNT,
    EXPECTED_NON_BLOCKED_COUNT,
    EXPECTED_PATHS,
    SEED_NOW,
    TARGET_KEYS,
    build_seed,
    load_into,
    to_snapshot,
)
from contracts import Feasibility


def loaded():
    repo = InMemoryGraphRepository(clock=lambda: SEED_NOW)
    seed = load_into(repo)
    return repo.snapshot(), seed


def combine(statuses):
    if Feasibility.BLOCKED in statuses:
        return Feasibility.BLOCKED
    if any(s != Feasibility.FEASIBLE_UNDER_MODEL for s in statuses):
        return Feasibility.CONDITIONAL
    return Feasibility.FEASIBLE_UNDER_MODEL


def test_repository_snapshot_matches_direct_snapshot():
    snap, seed = loaded()
    direct = to_snapshot(seed)
    assert {e.edge_id: e for e in snap.edges} == {e.edge_id: e for e in direct.edges}
    assert {e.entity_id: e for e in snap.entities} == {
        e.entity_id: e for e in direct.entities
    }
    assert len(snap.entities) == 11
    assert len(snap.edges) == 13


def test_expected_paths_are_well_formed():
    snap, seed = loaded()
    entries = {seed.entity_ids[k] for k in ENTRY_KEYS}
    targets = {seed.entity_ids[k] for k in TARGET_KEYS}
    for keys, _ in EXPECTED_PATHS:
        edges = [snap.get_edge(seed.edge_ids[k]) for k in keys]
        assert edges[0].source_id in entries, keys
        assert edges[-1].target_id in targets, keys
        for a, b in zip(edges, edges[1:]):
            assert a.target_id == b.source_id, keys
    assert len(seed.expected_paths()) == len(EXPECTED_PATHS)  # unique path ids


def test_fixture_status_matches_edge_level_rule():
    snap, seed = loaded()
    for keys, expected in EXPECTED_PATHS:
        statuses = [
            snap.check_transition(seed.edge_ids[k], {}).status for k in keys
        ]
        assert combine(statuses) == expected, keys


def test_fixture_counts():
    blocked = sum(1 for _, s in EXPECTED_PATHS if s == "blocked")
    assert blocked == EXPECTED_BLOCKED_COUNT
    assert len(EXPECTED_PATHS) - blocked == EXPECTED_NON_BLOCKED_COUNT


def test_readme_scenario_alice_to_ops_role():
    snap, seed = loaded()
    alice = seed.entity_ids["alice"]
    dev = seed.entity_ids["dev-role"]
    ops = seed.entity_ids["ops-role"]
    assert seed.edge_ids["E1"] in {e.edge_id for e in snap.get_neighbors(alice)}
    e3 = snap.get_edge(seed.edge_ids["E3"])
    assert (e3.source_id, e3.target_id) == (dev, ops)


def test_special_edges():
    snap, seed = loaded()
    assert snap.check_transition(seed.edge_ids["E11"], {}).reason == "edge_expired"
    assert snap.get_edge(seed.edge_ids["E2"]).status == "stale"
    assert snap.get_edge(seed.edge_ids["E10"]).status == "unknown"
    assert (
        snap.check_transition(seed.edge_ids["E9"], {}).reason
        == "conditions_require_evaluation"
    )