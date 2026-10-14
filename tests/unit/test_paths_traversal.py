from backend.paths.traversal import traverse
from contracts.paths import Feasibility, PathOptions

from path_graphs import build_graph


def node_sets(outcome):
    return {p.node_ids for p in outcome.paths}


def test_finds_both_routes_to_target():
    out = traverse(build_graph(), "dev", ["bucket"], PathOptions())
    assert node_sets(out) == {
        ("dev", "ops", "admin", "bucket"),
        ("dev", "backup", "bucket"),
    }
    assert not out.truncated


def test_cycle_does_not_loop_or_revisit():
    out = traverse(build_graph(), "dev", ["bucket"], PathOptions())
    for p in out.paths:
        assert len(set(p.node_ids)) == len(p.node_ids)


def test_max_depth_limits_and_reports_truncation():
    out = traverse(build_graph(), "dev", ["bucket"], PathOptions(max_depth=2))
    assert node_sets(out) == {("dev", "backup", "bucket")}
    assert out.truncated and out.truncation_reason == "max_depth"


def test_max_paths_limits_and_reports_truncation():
    out = traverse(build_graph(), "dev", ["bucket"], PathOptions(max_paths=1))
    assert len(out.paths) == 1
    assert out.truncated and out.truncation_reason == "max_paths"


def test_blocked_edge_is_rejected_and_counted():
    g = build_graph({"dev>backup": "invalidated"})
    out = traverse(g, "dev", ["bucket"], PathOptions())
    assert node_sets(out) == {("dev", "ops", "admin", "bucket")}
    assert out.blocked_rejected == 1


def test_include_blocked_keeps_path_with_blocked_transition():
    g = build_graph({"dev>backup": "invalidated"})
    out = traverse(g, "dev", ["bucket"], PathOptions(include_blocked=True))
    assert len(out.paths) == 2
    backup = next(p for p in out.paths if p.node_ids[1] == "backup")
    assert backup.transitions[0].status is Feasibility.BLOCKED
    assert out.blocked_rejected == 0


def test_allowed_relation_types_restricts_steps():
    out = traverse(
        build_graph(), "dev", ["bucket"],
        PathOptions(allowed_relation_types=frozenset({"can_assume"})),
    )
    assert out.paths == ()


def test_entry_that_is_a_target_yields_nothing():
    out = traverse(build_graph(), "bucket", ["bucket"], PathOptions())
    assert out.paths == ()