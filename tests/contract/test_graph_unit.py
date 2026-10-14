from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from contracts.entities import Entity
from contracts.graph import GraphSnapshot
from contracts.relationships import Relationship
from contracts.vocab import NodeType, RelationType

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)


def make_entities():
    return [
        Entity(entity_id=x, entity_type=NodeType.IAM_ROLE, name=x) for x in "abc"
    ]


def make_edges():
    return [
        Relationship(source_id="a", target_id="b", relation_type=RelationType.CAN_ASSUME),
        Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.CAN_ASSUME,
            discriminator="p2",
        ),
        Relationship(source_id="b", target_id="c", relation_type=RelationType.CAN_READ),
    ]


def make_snapshot(**overrides):
    data = {
        "version": "v1",
        "created_at": NOW,
        "entities": make_entities(),
        "edges": make_edges(),
    }
    data.update(overrides)
    return GraphSnapshot(**data)


def test_lookups():
    snap = make_snapshot()
    assert snap.get_entity("a").name == "a"
    assert len(snap.list_entities()) == 3
    edge = snap.list_edges()[0]
    assert snap.get_edge(edge.edge_id) == edge


def test_missing_returns_none():
    snap = make_snapshot()
    assert snap.get_entity("zzz") is None
    assert snap.get_edge("e_nope") is None


def test_outgoing_edges():
    snap = make_snapshot()
    assert len(snap.outgoing_edges("a")) == 2
    assert len(snap.outgoing_edges("b")) == 1
    assert snap.outgoing_edges("c") == ()


def test_duplicate_entity_rejected():
    with pytest.raises(ValidationError):
        make_snapshot(entities=make_entities() + make_entities()[:1])


def test_dangling_edge_rejected():
    bad = Relationship(source_id="a", target_id="ghost", relation_type=RelationType.CAN_READ)
    with pytest.raises(ValidationError):
        make_snapshot(edges=[bad])


def test_naive_created_at_rejected():
    with pytest.raises(ValidationError):
        make_snapshot(created_at=datetime(2026, 10, 14, 12, 0))


def test_fork_leaves_original_untouched():
    snap = make_snapshot()
    victim = snap.list_edges()[0].edge_id
    forked = snap.fork([victim])
    assert len(snap.list_edges()) == 3
    assert len(forked.list_edges()) == 2
    assert forked.get_edge(victim) is None
    assert forked.created_at == snap.created_at


def test_fork_version_is_deterministic_and_distinct():
    snap = make_snapshot()
    victim = snap.list_edges()[0].edge_id
    assert snap.fork([victim]).version == snap.fork([victim]).version
    assert snap.fork([victim]).version != snap.version


def test_fork_rejects_unknown_edge():
    with pytest.raises(ValueError):
        make_snapshot().fork(["e_does_not_exist"])