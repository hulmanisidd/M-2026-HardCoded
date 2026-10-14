from backend.paths import discover_paths, find_paths
from contracts.paths import Feasibility, PathOptions

from path_graphs import build_graph, edge_id


def test_finds_paths_shortest_first_with_graph_version():
    g = build_graph()
    paths = find_paths(g, ["dev"], ["bucket"])
    assert [p.node_ids for p in paths] == [
        ("dev", "backup", "bucket"),
        ("dev", "ops", "admin", "bucket"),
    ]
    assert all(p.graph_version == "v1" for p in paths)
    assert all(p.feasibility_status is Feasibility.FEASIBLE_UNDER_MODEL for p in paths)


def test_every_path_references_real_edges():
    g = build_graph()
    for p in find_paths(g, ["dev"], ["bucket"]):
        assert all(g.get_edge(e) is not None for e in p.edge_ids)


def test_stale_edge_makes_only_that_path_conditional():
    g = build_graph({"dev>backup": "stale"})
    by_route = {p.node_ids[1]: p for p in find_paths(g, ["dev"], ["bucket"])}
    assert by_route["backup"].feasibility_status is Feasibility.CONDITIONAL
    assert by_route["ops"].feasibility_status is Feasibility.FEASIBLE_UNDER_MODEL


def test_explanations_describe_each_step():
    p = find_paths(build_graph(), ["dev"], ["bucket"])[0]
    assert p.explanations[0].startswith("Step 1: dev --can_assume--> backup")
    assert any("not evidence of an attack" in line for line in p.explanations)


def test_duplicate_entry_points_do_not_duplicate_paths():
    assert len(find_paths(build_graph(), ["dev", "dev"], ["bucket"])) == 2


def test_path_ids_are_unique_and_stable():
    a = find_paths(build_graph(), ["dev"], ["bucket"])
    b = find_paths(build_graph(), ["dev"], ["bucket"])
    assert [p.path_id for p in a] == [p.path_id for p in b]
    assert len({p.path_id for p in a}) == len(a)


def test_stats_report_blocked_rejections():
    g = build_graph({"dev>backup": "invalidated"})
    result = discover_paths(g, ["dev"], ["bucket"])
    assert result.stats.paths_found == 1
    assert result.stats.blocked_transitions_rejected == 1
    assert not result.stats.truncated


def test_truncation_is_reported():
    result = discover_paths(build_graph(), ["dev"], ["bucket"], PathOptions(max_paths=1))
    assert result.stats.truncated and result.stats.truncation_reason == "max_paths"


def test_revoked_edge_removes_path_after_recompute():
    g = build_graph()
    fork = g.fork([edge_id(g, "backup", "bucket")])
    paths = find_paths(fork, ["dev"], ["bucket"])
    assert [p.node_ids for p in paths] == [("dev", "ops", "admin", "bucket")]
    assert paths[0].graph_version == fork.version