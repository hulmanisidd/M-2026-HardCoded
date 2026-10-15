from datetime import datetime, timedelta, timezone

import pytest

from backend.graph.memory_repository import InMemoryGraphRepository
from contracts import (
    EdgeStatus, Entity, Feasibility, NodeType, Relationship, RelationType,
)

NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)


def make_repo(clock=lambda: NOW):
    repo = InMemoryGraphRepository(clock=clock)
    repo.upsert_entity(Entity(entity_id="user-a", entity_type=NodeType.IAM_USER, name="a"))
    repo.upsert_entity(Entity(entity_id="role-b", entity_type=NodeType.IAM_ROLE, name="b"))
    repo.upsert_entity(Entity(entity_id="bucket-c", entity_type=NodeType.S3_BUCKET, name="c"))
    return repo


def edge(status=EdgeStatus.CONFIRMED, **kw):
    return Relationship(
        source_id="user-a", target_id="role-b",
        relation_type=RelationType.CAN_ASSUME, status=status, **kw,
    )


def test_create_read_update_invalidate():
    repo = make_repo()
    e = edge()
    assert repo.upsert_edge(e).changed
    assert repo.get_edge(e.edge_id) == e
    upd = repo.upsert_edge(edge(status=EdgeStatus.STALE))
    assert upd.changed and repo.get_edge(e.edge_id).status is EdgeStatus.STALE
    assert repo.invalidate_edge(e.edge_id).changed
    assert repo.get_edge(e.edge_id).status is EdgeStatus.INVALIDATED


def test_replay_is_idempotent():
    repo = make_repo()
    e = edge()
    repo.upsert_edge(e)
    v1 = repo.snapshot().version
    assert not repo.upsert_edge(e).changed
    assert repo.snapshot().version == v1
    repo.invalidate_edge(e.edge_id)
    assert not repo.invalidate_edge(e.edge_id).changed


def test_snapshot_version_is_stable_and_content_based():
    a, b = make_repo(), make_repo()
    a.upsert_edge(edge())
    b.upsert_edge(edge())
    assert a.snapshot().version == b.snapshot().version
    b.invalidate_edge(edge().edge_id)
    assert a.snapshot().version != b.snapshot().version



def test_edge_with_unknown_endpoint_is_rejected_without_partial_write():
    repo = make_repo()
    bad = Relationship(
        source_id="user-a",
        target_id="ghost",
        relation_type=RelationType.CAN_READ,
    )

    edges_before = repo.snapshot().edges

    with pytest.raises(ValueError):
        repo.upsert_edge(bad)

    # The rejected edge must not have been stored.
    assert repo.get_edge(bad.edge_id) is None
    assert repo.snapshot().edges == edges_before


def test_edge_can_be_retried_after_missing_endpoint_is_added():
    repo = make_repo()
    bad = Relationship(
        source_id="user-a",
        target_id="ghost",
        relation_type=RelationType.CAN_READ,
    )

    with pytest.raises(ValueError):
        repo.upsert_edge(bad)

    # Add the missing endpoint and retry the same edge.
    repo.upsert_entity(
        Entity(entity_id="ghost", entity_type=NodeType.S3_BUCKET, name="ghost")
    )
    change = repo.upsert_edge(bad)

    assert change.changed is True
    assert repo.get_edge(bad.edge_id) == bad



def test_invalidate_unknown_edge_raises():
    with pytest.raises(KeyError):
        make_repo().invalidate_edge("missing")


def test_expired_edge_is_not_current():
    repo = make_repo()
    e = edge(valid_until=NOW - timedelta(days=1), valid_from=NOW - timedelta(days=10))
    repo.upsert_edge(e)
    assert repo.snapshot().check_transition(e.edge_id, {}).status is Feasibility.BLOCKED


def test_stale_and_unknown_status_are_preserved_not_feasible():
    repo = make_repo()
    for status in (EdgeStatus.STALE, EdgeStatus.UNKNOWN):
        e = edge(status=status)
        repo.upsert_edge(e)
        assert repo.get_edge(e.edge_id).status is status
        assert repo.snapshot().check_transition(e.edge_id, {}).status is Feasibility.CONDITIONAL


def test_network_style_edge_does_not_grant_data_access():
    # No CAN_READ edge exists, so there is no authorization to the bucket.
    repo = make_repo()
    repo.upsert_edge(edge())
    assert repo.get_neighbors("role-b") == []


def test_neighbors_are_deterministic():
    repo = make_repo()
    repo.upsert_edge(edge())
    repo.upsert_edge(Relationship(source_id="user-a", target_id="bucket-c",
                                  relation_type=RelationType.CAN_READ,
                                  status=EdgeStatus.CONFIRMED))
    ids = [e.edge_id for e in repo.get_neighbors("user-a")]
    assert ids == sorted(ids) and len(ids) == 2