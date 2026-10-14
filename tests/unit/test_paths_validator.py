import pytest

from backend.paths.validator import combine_statuses, validate_path
from contracts.paths import Feasibility

from path_graphs import build_graph, edge_id


def test_all_confirmed_is_feasible():
    g = build_graph()
    ids = [edge_id(g, "dev", "backup"), edge_id(g, "backup", "bucket")]
    status, results = validate_path(g, ids, {})
    assert status is Feasibility.FEASIBLE_UNDER_MODEL
    assert len(results) == 2


def test_stale_edge_makes_path_conditional():
    g = build_graph({"dev>backup": "stale"})
    ids = [edge_id(g, "dev", "backup"), edge_id(g, "backup", "bucket")]
    assert validate_path(g, ids, {})[0] is Feasibility.CONDITIONAL


def test_blocked_beats_conditional():
    g = build_graph({"dev>backup": "stale", "backup>bucket": "invalidated"})
    ids = [edge_id(g, "dev", "backup"), edge_id(g, "backup", "bucket")]
    assert validate_path(g, ids, {})[0] is Feasibility.BLOCKED


def test_empty_is_rejected():
    with pytest.raises(ValueError):
        combine_statuses([])