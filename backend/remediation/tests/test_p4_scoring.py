from datetime import datetime, timezone

from contracts import (
    AttackPath, Criticality, EdgeStatus, Entity, FeasibilityStatus,
    GraphSnapshot, NodeType, RelationType, Relationship, make_path_id,
)
from backend.remediation.scoring import rank_paths

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def ent(i, t=NodeType.IAM_ROLE, c=Criticality.LOW):
    return Entity(entity_id=i, entity_type=t, name=i, criticality=c)


def edge(s, t, status=EdgeStatus.CONFIRMED, rel=RelationType.CAN_ASSUME, **kw):
    return Relationship(source_id=s, target_id=t, relation_type=rel, status=status, **kw)


def path(snap, nodes, feas=FeasibilityStatus.FEASIBLE_UNDER_MODEL):
    edges = []
    for a, b in zip(nodes, nodes[1:]):
        edges.append(next(e.edge_id for e in snap.edges if e.source_id == a and e.target_id == b))
    return AttackPath(path_id=make_path_id(tuple(edges)), graph_version=snap.version,
                      entry_node_id=nodes[0], target_node_id=nodes[-1],
                      node_ids=tuple(nodes), edge_ids=tuple(edges), feasibility_status=feas)


def snap_of(entities, edges):
    return GraphSnapshot(version="v1", created_at=NOW, entities=tuple(entities), edges=tuple(edges))


def test_higher_impact_ranks_above_equivalent_lower_impact():
    s = snap_of([ent("u", NodeType.IAM_USER), ent("lo", NodeType.S3_BUCKET, Criticality.LOW),
                 ent("hi", NodeType.S3_BUCKET, Criticality.CRITICAL)],
                [edge("u", "lo", rel=RelationType.CAN_READ), edge("u", "hi", rel=RelationType.CAN_READ)])
    ranked = rank_paths([path(s, ["u", "lo"]), path(s, ["u", "hi"])], s)
    assert ranked[0].impact_score == 1.0 and ranked[0].risk_score > ranked[1].risk_score


def test_longer_path_scores_lower():
    s = snap_of([ent("u", NodeType.IAM_USER), ent("r"), ent("b", NodeType.S3_BUCKET, Criticality.HIGH)],
                [edge("u", "b", rel=RelationType.CAN_READ), edge("u", "r"),
                 edge("r", "b", rel=RelationType.CAN_READ)])
    short, long_ = rank_paths([path(s, ["u", "b"]), path(s, ["u", "r", "b"])], s)
    assert short.path_id != long_.path_id and short.risk_score > long_.risk_score


def test_unknown_edge_gives_none_not_a_normal_score():
    s = snap_of([ent("u", NodeType.IAM_USER), ent("b", NodeType.S3_BUCKET, Criticality.CRITICAL)],
                [edge("u", "b", EdgeStatus.UNKNOWN, RelationType.CAN_READ)])
    (a,) = rank_paths([path(s, ["u", "b"], FeasibilityStatus.CONDITIONAL)], s)
    assert a.risk_score is None and a.likelihood_score is None
    assert a.confidence == "unknown" and a.unknowns


def test_stale_and_conditions_lower_score_and_confidence():
    entities = [ent("u", NodeType.IAM_USER), ent("b", NodeType.S3_BUCKET, Criticality.HIGH)]
    good = snap_of(entities, [edge("u", "b", rel=RelationType.CAN_READ)])
    stale = snap_of(entities, [edge("u", "b", EdgeStatus.STALE, RelationType.CAN_READ,
                                    conditions={"mfa": True})])
    g = rank_paths([path(good, ["u", "b"])], good)[0]
    st = rank_paths([path(stale, ["u", "b"], FeasibilityStatus.CONDITIONAL)], stale)[0]
    assert st.risk_score < g.risk_score and g.confidence == "high" and st.confidence == "low"


def test_blocked_path_has_zero_risk_and_unknown_ranks_last_but_is_kept():
    entities = [ent("u", NodeType.IAM_USER), ent("b", NodeType.S3_BUCKET, Criticality.HIGH),
                ent("c", NodeType.S3_BUCKET, Criticality.HIGH)]
    s = snap_of(entities, [edge("u", "b", rel=RelationType.CAN_READ),
                           edge("u", "c", EdgeStatus.UNKNOWN, RelationType.CAN_READ)])
    ranked = rank_paths([path(s, ["u", "c"], FeasibilityStatus.CONDITIONAL),
                         path(s, ["u", "b"], FeasibilityStatus.BLOCKED)], s)
    assert len(ranked) == 2 and ranked[0].risk_score == 0.0 and ranked[1].risk_score is None


def test_does_not_mutate_snapshot_and_is_deterministic():
    s = snap_of([ent("u", NodeType.IAM_USER), ent("b", NodeType.S3_BUCKET, Criticality.HIGH)],
                [edge("u", "b", rel=RelationType.CAN_READ)])
    p = path(s, ["u", "b"])
    before = s.model_dump_json()
    assert rank_paths([p], s) == rank_paths([p], s)
    assert s.model_dump_json() == before