"""Shared fixture graph for rerouting tests.

    dev -> ops -> bucket          (primary, 2 hops)
    dev -> backup -> bucket       (candidate backup, 2 hops)
    attacker -> backup            (untrusted entry that can reach the backup role)
    dev -> escalator -> bucket    (escalator uses can_modify_policy: not legitimate)
"""
from datetime import datetime, timezone

from contracts.entities import Entity
from contracts.graph import GraphSnapshot
from contracts.relationships import Relationship
from contracts.vocab import Criticality, NodeType, RelationType

NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)
A, R, M = RelationType.CAN_ASSUME, RelationType.CAN_READ, RelationType.CAN_MODIFY_POLICY

NODES = {
    "dev": NodeType.IAM_USER, "ops": NodeType.IAM_ROLE, "backup": NodeType.IAM_ROLE,
    "escalator": NodeType.IAM_ROLE, "attacker": NodeType.EXTERNAL_PRINCIPAL,
    "bucket": NodeType.S3_BUCKET,
}
BASE_EDGES = [
    ("dev", A, "ops"), ("ops", R, "bucket"),
    ("dev", A, "backup"), ("backup", R, "bucket"),
    ("dev", A, "escalator"), ("escalator", M, "bucket"),
]


def build(statuses=None, conditions=None, no_evidence=(), extra=(), drop=(), version="v1"):
    """statuses/conditions keyed by 'src>dst'. no_evidence: keys without evidence ids."""
    statuses, conditions = statuses or {}, conditions or {}
    ents = tuple(
        Entity(entity_id=n, entity_type=t, name=n,
               criticality=Criticality.CRITICAL if n == "bucket" else Criticality.LOW)
        for n, t in NODES.items()
    )
    edges = []
    for s, r, t in [*BASE_EDGES, *extra]:
        key = f"{s}>{t}"
        if key in drop:
            continue
        edges.append(Relationship(
            source_id=s, relation_type=r, target_id=t,
            status=statuses.get(key, "confirmed"),
            conditions=conditions.get(key, {}),
            evidence_ids=() if key in no_evidence else (f"ev:{key}",),
        ))
    return GraphSnapshot(version=version, created_at=NOW, entities=ents, edges=tuple(edges))


def eid(g, src, dst):
    return next(e.edge_id for e in g.edges if e.source_id == src and e.target_id == dst)