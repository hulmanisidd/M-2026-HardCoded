from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from contracts.entities import Entity
from contracts.graph import GraphSnapshot
from contracts.paths import Feasibility
from contracts.relationships import Relationship
from contracts.vocab import NodeType, RelationType


NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)


def make_graph(status="confirmed", conditions=None):
    entities = (
        Entity(entity_id="user-a", entity_type=NodeType.IAM_USER, name="user"),
        Entity(entity_id="role-b", entity_type=NodeType.IAM_ROLE, name="role"),
    )
    edge = Relationship(
        source_id="user-a",
        target_id="role-b",
        relation_type=RelationType.CAN_ASSUME,
        status=status,
        conditions=conditions or {},
    )
    return GraphSnapshot(
        version="v1",
        created_at=NOW,
        entities=entities,
        edges=(edge,),
    ), edge


def test_graph_looks_up_entities_and_edges():
    graph, edge = make_graph()
    assert graph.get_entity("user-a").name == "user"
    assert graph.get_edge(edge.edge_id) == edge
    assert graph.get_neighbors("user-a") == [edge]


def test_confirmed_unconditional_edge_is_feasible():
    graph, edge = make_graph()
    result = graph.check_transition(edge.edge_id, {})
    assert result.status is Feasibility.FEASIBLE_UNDER_MODEL


def test_unknown_edge_is_blocked():
    graph, _ = make_graph()
    assert graph.check_transition("missing", {}).status is Feasibility.BLOCKED


def test_unknown_edge_status_is_conditional():
    graph, edge = make_graph(status="unknown")
    assert graph.check_transition(edge.edge_id, {}).status is Feasibility.CONDITIONAL


def test_conditional_edge_is_not_assumed_feasible():
    graph, edge = make_graph(conditions={"external_id": "required"})
    assert graph.check_transition(edge.edge_id, {}).status is Feasibility.CONDITIONAL


def test_duplicate_entities_are_rejected():
    graph, _ = make_graph()
    with pytest.raises(ValidationError):
        GraphSnapshot(
            version="v2",
            created_at=NOW,
            entities=graph.entities + (graph.entities[0],),
            edges=(),
        )


def test_fork_removes_edge_without_mutating_original():
    graph, edge = make_graph()
    fork = graph.fork([edge.edge_id])
    assert graph.get_edge(edge.edge_id) is not None
    assert fork.get_edge(edge.edge_id) is None
    assert fork.version != graph.version


def test_fork_rejects_unknown_edge():
    graph, _ = make_graph()
    with pytest.raises(ValueError, match="unknown edge ids"):
        graph.fork(["missing"])
