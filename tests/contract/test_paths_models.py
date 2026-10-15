import pytest
from pydantic import ValidationError

from contracts.paths import AttackPath, FeasibilityStatus, make_path_id


def make(**overrides):
    data = dict(
        path_id="p1",
        graph_version="v1",
        entry_node_id="a",
        target_node_id="c",
        node_ids=("a", "b", "c"),
        edge_ids=("e1", "e2"),
        feasibility_status=FeasibilityStatus.FEASIBLE_UNDER_MODEL,
    )
    data.update(overrides)
    return AttackPath(**data)


def test_valid_path():
    p = make()
    assert p.entry_node_id == "a" and p.target_node_id == "c"
    assert p.evidence_ids == () and p.explanations == ()


def test_node_edge_count_mismatch():
    with pytest.raises(ValidationError):
        make(node_ids=("a", "c"))


def test_entry_and_target_must_match_ends():
    with pytest.raises(ValidationError):
        make(entry_node_id="x")
    with pytest.raises(ValidationError):
        make(target_node_id="x")


def test_rejects_cycles_and_reused_edges():
    with pytest.raises(ValidationError):
        make(entry_node_id="a", target_node_id="a",
             node_ids=("a", "b", "a"), edge_ids=("e1", "e2"))
    with pytest.raises(ValidationError):
        make(edge_ids=("e1", "e1"))


def test_rejects_empty_and_bad_status():
    with pytest.raises(ValidationError):
        make(node_ids=("a",), edge_ids=())
    with pytest.raises(ValidationError):
        make(feasibility_status="maybe")


def test_frozen_and_extra_forbidden():
    p = make()
    with pytest.raises(ValidationError):
        p.path_id = "x"
    with pytest.raises(ValidationError):
        make(unknown_field=1)


def test_make_path_id_is_stable_and_order_sensitive():
    assert make_path_id(("e1", "e2")) == make_path_id(("e1", "e2"))
    assert make_path_id(("e1", "e2")) != make_path_id(("e2", "e1"))
    assert make_path_id(("e1", "e2")).startswith("p_")