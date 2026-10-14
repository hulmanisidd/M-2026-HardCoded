from datetime import datetime, timezone

from backend.paths import find_paths
from contracts.entities import Entity
from contracts.graph import GraphSnapshot
from contracts.paths import AttackPath, PathOptions
from contracts.relationships import Relationship
from contracts.vocab import NodeType, RelationType


def test_find_paths_returns_contract_valid_attack_paths():
    now = datetime(2026, 10, 14, tzinfo=timezone.utc)
    entities = (
        Entity(entity_id="user-a", entity_type=NodeType.IAM_USER, name="User A"),
        Entity(entity_id="role-b", entity_type=NodeType.IAM_ROLE, name="Role B"),
    )
    edge = Relationship(
        source_id="user-a",
        target_id="role-b",
        relation_type=RelationType.CAN_ASSUME,
        status="confirmed",
    )
    snapshot = GraphSnapshot(
        version="contract-v1",
        created_at=now,
        entities=entities,
        edges=(edge,),
    )

    paths = find_paths(snapshot, ["user-a"], ["role-b"], PathOptions())

    assert isinstance(paths, list)
    assert len(paths) == 1
    assert all(isinstance(path, AttackPath) for path in paths)
    assert paths[0].node_ids == ("user-a", "role-b")
    assert paths[0].graph_version == "contract-v1"
