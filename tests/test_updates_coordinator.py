
from datetime import datetime, timezone

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.models import ChangeKind, GraphChange
from backend.updates.coordinator import UpdateCoordinator
from contracts import Entity, Relationship, EdgeStatus
from contracts.vocab import NodeType, Criticality, RelationType


def make_entity(entity_id: str) -> Entity:
    return Entity(
        entity_id=entity_id,
        entity_type=NodeType.__args__[0] if hasattr(NodeType, "__args__") else list(NodeType)[0],
        name=entity_id,
        criticality=Criticality.LOW,
    )


def make_edge(source: str, target: str) -> Relationship:
    return Relationship(
        source_id=source,
        target_id=target,
        relation_type=RelationType.CAN_ASSUME,
        status=EdgeStatus.CONFIRMED,
    )


def make_coordinator(repo, entries=("a",), targets=("c",)):
    return UpdateCoordinator(
        graph_reader_factory=repo.snapshot,
        entry_points=entries,
        targets=targets,
    )


def test_initialize_discovers_and_indexes_paths():
    repo = InMemoryGraphRepository()
    repo.upsert_entity(make_entity("a"))
    repo.upsert_entity(make_entity("b"))
    repo.upsert_entity(make_entity("c"))
    repo.upsert_edge(make_edge("a", "b"))
    repo.upsert_edge(make_edge("b", "c"))

    coordinator = make_coordinator(repo)
    result = coordinator.initialize()

    assert result.applied is True
    assert result.reason == "initial_discovery"
    assert len(coordinator.dependency_index) == 1
    assert result.recomputed_path_ids


def test_invalidating_edge_drops_path():
    repo = InMemoryGraphRepository()
    repo.upsert_entity(make_entity("a"))
    repo.upsert_entity(make_entity("b"))
    repo.upsert_entity(make_entity("c"))
    repo.upsert_edge(make_edge("a", "b"))
    edge_change = repo.upsert_edge(make_edge("b", "c"))

    coordinator = make_coordinator(repo)
    coordinator.initialize()

    change = repo.invalidate_edge(edge_change.subject_id)
    result = coordinator.handle_change(change)

    assert result.applied is True
    assert len(coordinator.dependency_index) == 0
    assert result.dropped_path_ids


def test_replayed_change_is_ignored():
    repo = InMemoryGraphRepository()
    repo.upsert_entity(make_entity("a"))
    repo.upsert_entity(make_entity("b"))
    repo.upsert_edge(make_edge("a", "b"))

    coordinator = make_coordinator(repo, targets=("b",))
    coordinator.initialize()

    change = GraphChange(
        kind=ChangeKind.EDGE_UPDATED,
        subject_id="edge-x",
        changed=False,
        version=repo.snapshot().version,
    )

    result = coordinator.handle_change(change)

    assert result.applied is False
    assert result.reason == "replayed_change"


def test_version_mismatch_is_rejected():
    repo = InMemoryGraphRepository()
    repo.upsert_entity(make_entity("a"))
    repo.upsert_entity(make_entity("b"))
    repo.upsert_edge(make_edge("a", "b"))

    coordinator = make_coordinator(repo, targets=("b",))
    coordinator.initialize()

    change = GraphChange(
        kind=ChangeKind.EDGE_ADDED,
        subject_id="edge-x",
        changed=True,
        version="not-the-current-version",
    )

    result = coordinator.handle_change(change)

    assert result.applied is False
    assert result.reason == "graph_version_mismatch"
