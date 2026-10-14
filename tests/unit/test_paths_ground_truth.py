import json
from datetime import datetime, timezone
from pathlib import Path

from backend.paths.engine import discover_paths
from contracts.entities import Entity
from contracts.graph import GraphSnapshot
from contracts.paths import PathOptions
from contracts.relationships import Relationship
from contracts.vocab import Criticality, NodeType, RelationType

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "expected_results" / "iam_small.json"
FIX = json.loads(FIXTURE.read_text())
NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)


def build_fixture_graph(data) -> GraphSnapshot:
    entities = tuple(
        Entity(
            entity_id=name,
            entity_type=NodeType[kind],
            name=name,
            criticality=Criticality.CRITICAL if name in data["critical"] else Criticality.LOW,
        )
        for name, kind in data["nodes"].items()
    )
    edges = tuple(
        Relationship(
            source_id=s, relation_type=RelationType[r], target_id=t, status=status
        )
        for s, r, t, status in data["edges"]
    )
    return GraphSnapshot(version=data["graph_version"], created_at=NOW, entities=entities, edges=edges)


def _run(**opts):
    graph = build_fixture_graph(FIX)
    return discover_paths(graph, FIX["entries"], FIX["targets"], PathOptions(**opts))


def _got(res):
    return {(p.node_ids, p.feasibility_status.value) for p in res.paths}


def test_default_matches_hand_derived_paths():
    res = _run(max_depth=4)
    want = {(tuple(n), s) for n, s in FIX["expected_default"]}
    assert _got(res) == want
    assert not res.stats.truncated
    assert res.graph_version == FIX["graph_version"]
    present = {p.node_ids for p in res.paths}
    for bad in FIX["must_not_appear"]:
        assert tuple(bad) not in present


def test_include_blocked_adds_only_the_invalidated_route():
    res = _run(max_depth=4, include_blocked=True)
    want = {(tuple(n), s) for n, s in FIX["expected_default"]}
    want.add((("alice", "admin", "prod-db"), "blocked"))
    assert _got(res) == want


def test_max_depth_two_truncates_and_keeps_short_paths():
    res = _run(max_depth=2)
    assert _got(res) == {
        (("alice", "app", "prod-db"), "conditional"),
        (("ci-bot", "deploy", "prod-db"), "feasible_under_model"),
    }
    assert res.stats.truncated

def test_discovery_does_not_mutate_the_graph():
    graph = build_fixture_graph(FIX)
    before = graph.model_dump()
    discover_paths(graph, FIX["entries"], FIX["targets"], PathOptions(max_depth=4))
    assert graph.model_dump() == before


def test_unknown_entry_and_target_are_reported_not_silent():
    graph = build_fixture_graph(FIX)
    res = discover_paths(
        graph, ["alice", "user:ghost"], ["prod-db", "db:missing"], PathOptions(max_depth=4)
    )
    assert res.stats.unknown_entry_ids == ("user:ghost",)
    assert res.stats.unknown_target_ids == ("db:missing",)
    assert {p.entry_node_id for p in res.paths} == {"alice"}
    assert not res.stats.truncated


def test_only_unknown_entry_yields_no_paths_but_says_why():
    graph = build_fixture_graph(FIX)
    res = discover_paths(graph, ["user:ghost"], FIX["targets"])
    assert res.paths == ()
    assert res.stats.unknown_entry_ids == ("user:ghost",)

def test_paths_using_stale_app_prod_db_edge_returns_two_conditional_paths():
    from backend.paths import paths_using_edge

    graph = build_fixture_graph(FIX)
    result = discover_paths(graph, FIX["entries"], FIX["targets"], PathOptions(max_depth=4))
    stale_edge_id = next(
        edge.edge_id
        for edge in graph.edges
        if edge.source_id == "app" and edge.target_id == "prod-db"
    )

    affected = paths_using_edge(result.paths, stale_edge_id)

    assert len(affected) == 2
    assert {p.node_ids for p in affected} == {
        ("alice", "app", "prod-db"),
        ("ci-bot", "deploy", "app", "prod-db"),
    }
    assert all(p.feasibility_status.value == "conditional" for p in affected)
