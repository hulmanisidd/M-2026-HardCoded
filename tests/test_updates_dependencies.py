from backend.updates.dependencies import DependencyIndex
from backend.updates.models import GraphChange
from contracts.paths import AttackPath, FeasibilityStatus, make_path_id


def _path(nodes, edges):
    return AttackPath(
        path_id=make_path_id(tuple(edges)),
        graph_version="v1",
        entry_node_id=nodes[0],
        target_node_id=nodes[-1],
        node_ids=tuple(nodes),
        edge_ids=tuple(edges),
        feasibility_status=FeasibilityStatus.FEASIBLE_UNDER_MODEL,
    )


P1 = _path(["a", "b", "c"], ["e1", "e2"])
P2 = _path(["a", "d", "c"], ["e3", "e4"])
P3 = _path(["a", "b", "x"], ["e1", "e5"])  # shares e1 with P1


def test_affected_paths_only_returns_paths_using_the_edge():
    idx = DependencyIndex()
    idx.register([P1, P2, P3])
    assert idx.affected_paths(["e2"]) == (P1.path_id,)
    assert idx.affected_paths(["e1"]) == tuple(sorted([P1.path_id, P3.path_id]))


def test_unrelated_edge_affects_nothing():
    idx = DependencyIndex()
    idx.register([P1, P2])
    assert idx.affected_paths(["zzz"]) == ()


def test_register_twice_is_idempotent():
    idx = DependencyIndex()
    idx.register([P1])
    idx.register([P1])
    assert len(idx) == 1
    assert idx.paths_using("e1") == frozenset({P1.path_id})


def test_remove_cleans_the_notebook():
    idx = DependencyIndex()
    idx.register([P1, P3])
    idx.remove([P1.path_id])
    assert idx.paths_using("e1") == frozenset({P3.path_id})
    assert idx.paths_using("e2") == frozenset()


def test_touched_edges_ignore_added_edges():
    change = GraphChange(
        from_version="v1", to_version="v2",
        added_edge_ids=("new",), removed_edge_ids=("e1",), changed_edge_ids=("e3",),
    )
    assert change.touched_edge_ids == frozenset({"e1", "e3"})