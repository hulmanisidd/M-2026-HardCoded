from backend.remediation.scoring import assess_path, rank_paths
from backend.remediation.tests.p4_helpers import NOW, find_paths
from contracts import (
    EdgeStatus, Entity, GraphSnapshot, NodeType, RelationType, Relationship,
)


def _snap():
    ents = (
        Entity(entity_id="u", entity_type=NodeType.IAM_USER, name="u"),
        Entity(entity_id="t", entity_type=NodeType.S3_BUCKET, name="t"),  # criticality=None
    )
    edge = Relationship(source_id="u", target_id="t", relation_type=RelationType.CAN_READ,
                        status=EdgeStatus.CONFIRMED)
    return GraphSnapshot(version="v1", created_at=NOW, entities=ents, edges=(edge,))


def test_unknown_criticality_is_unknown_not_crash_not_safe():
    snap = _snap()
    paths = find_paths(snap, entry="u", targets=("t",))
    assert len(paths) == 1
    a = assess_path(paths[0], snap)
    assert a.risk_score is None  # never a normal-looking score
    assert a.unknowns  # and the reason is visible
    assert len(rank_paths(paths, snap)) == 1