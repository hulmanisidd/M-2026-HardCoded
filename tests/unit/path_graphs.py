from datetime import datetime, timezone

from contracts.entities import Entity
from contracts.graph import GraphSnapshot
from contracts.relationships import Relationship
from contracts.vocab import Criticality, NodeType, RelationType

NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)

ENTITIES = {
    "dev": NodeType.IAM_USER,
    "ops": NodeType.IAM_ROLE,
    "admin": NodeType.IAM_ROLE,
    "backup": NodeType.IAM_ROLE,
    "orphan": NodeType.IAM_ROLE,
    "bucket": NodeType.S3_BUCKET,
}

# (source, relation, target) - key used for status overrides is "src>dst"
EDGES = [
    ("dev", RelationType.CAN_ASSUME, "ops"),
    ("ops", RelationType.CAN_PASS_ROLE, "admin"),
    ("admin", RelationType.CAN_READ, "bucket"),
    ("dev", RelationType.CAN_ASSUME, "backup"),
    ("backup", RelationType.CAN_READ, "bucket"),
    ("ops", RelationType.CAN_ASSUME, "dev"),      # cycle back
    ("dev", RelationType.CAN_ASSUME, "orphan"),   # dead end
]


def build_graph(statuses: dict[str, str] | None = None) -> GraphSnapshot:
    """Two routes dev->bucket: dev>ops>admin>bucket and dev>backup>bucket."""
    statuses = statuses or {}
    entities = tuple(
        Entity(
            entity_id=name,
            entity_type=kind,
            name=name,
            criticality=Criticality.CRITICAL if name == "bucket" else Criticality.LOW,
        )
        for name, kind in ENTITIES.items()
    )
    edges = tuple(
        Relationship(
            source_id=s,
            relation_type=r,
            target_id=t,
            status=statuses.get(f"{s}>{t}", "confirmed"),
        )
        for s, r, t in EDGES
    )
    return GraphSnapshot(version="v1", created_at=NOW, entities=entities, edges=edges)


def edge_id(graph: GraphSnapshot, src: str, dst: str) -> str:
    return next(e.edge_id for e in graph.edges if e.source_id == src and e.target_id == dst)