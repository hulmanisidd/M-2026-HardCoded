
from datetime import datetime, timezone

from contracts import EdgeStatus, Entity, Relationship
from contracts import NodeType, RelationType
from backend.graph.memory_repository import InMemoryGraphRepository


NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


def make_repository():
    repo = InMemoryGraphRepository(clock=lambda: NOW)

    user = Entity(
        entity_id="user-a",
        entity_type=NodeType.IAM_USER,
        name="Test User",
    )
    role = Entity(
        entity_id="role-b",
        entity_type=NodeType.IAM_ROLE,
        name="Test Role",
    )

    repo.upsert_entity(user)
    repo.upsert_entity(role)

    edge = Relationship(
        edge_id="edge-1",
        source_id="user-a",
        target_id="role-b",
        relation_type=RelationType.CAN_ASSUME,
        status=EdgeStatus.CONFIRMED,
    )

    return repo, user, edge


def test_duplicate_entity_is_idempotent():
    repo, user, _ = make_repository()
    version_before = repo.snapshot().version

    result = repo.upsert_entity(user)

    assert result.changed is False
    assert result.version == version_before
    assert repo.snapshot().version == version_before


def test_duplicate_edge_is_idempotent():
    repo, _, edge = make_repository()
    repo.upsert_edge(edge)
    version_before = repo.snapshot().version

    result = repo.upsert_edge(edge)

    assert result.changed is False
    assert result.version == version_before
    assert repo.snapshot().version == version_before


def test_repeated_invalidation_is_idempotent():
    repo, _, edge = make_repository()
    repo.upsert_edge(edge)

    first = repo.invalidate_edge(edge.edge_id)
    invalidated_version = first.version

    assert first.changed is True
    assert repo.get_edge(edge.edge_id).status == EdgeStatus.INVALIDATED

    second = repo.invalidate_edge(edge.edge_id)

    assert second.changed is False
    assert second.version == invalidated_version
    assert repo.snapshot().version == invalidated_version


def test_replay_does_not_resurrect_invalidated_edge():
    repo, _, edge = make_repository()
    repo.upsert_edge(edge)
    repo.invalidate_edge(edge.edge_id)

    version_before = repo.snapshot().version

    # Replay the old, confirmed relationship.
    result = repo.upsert_edge(edge)

    assert result.changed is False
    assert result.version == version_before
    assert repo.get_edge(edge.edge_id).status == EdgeStatus.INVALIDATED
    assert repo.snapshot().version == version_before


def test_explicit_reinstatement_is_allowed():
    repo, _, edge = make_repository()
    repo.upsert_edge(edge)
    repo.invalidate_edge(edge.edge_id)

    result = repo.upsert_edge(edge, reinstate=True)

    assert result.changed is True
    assert repo.get_edge(edge.edge_id).status == EdgeStatus.CONFIRMED
    assert result.version == repo.snapshot().version
