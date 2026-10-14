from datetime import datetime, timezone

from contracts import (
    AttackPath, Criticality, EdgeStatus, Entity, FeasibilityStatus, GraphSnapshot,
    NodeType, RelationType, Relationship, make_path_id,
)
from backend.remediation.candidates import generate_candidates
from backend.remediation.simulation import recommend, simulate_plan

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def find_paths(snap, entry="u", targets=("b", "b2"), max_depth=5):
    """Tiny TEST-ONLY simple-path DFS standing in for P3 (confirmed edges only)."""
    out = []

    def dfs(node, nodes, edges):
        if node in targets and edges:
            out.append(AttackPath(path_id=make_path_id(tuple(edges)), graph_version=snap.version,
                                  entry_node_id=entry, target_node_id=node, node_ids=tuple(nodes),
                                  edge_ids=tuple(edges),
                                  feasibility_status=FeasibilityStatus.FEASIBLE_UNDER_MODEL))
            return
        if len(edges) >= max_depth:
            return
        for e in snap.get_neighbors(node):
            if e.target_id not in nodes:
                dfs(e.target_id, nodes + [e.target_id], edges + [e.edge_id])

    dfs(entry, [entry], [])
    return out


def build():
    ents = [Entity(entity_id="u", entity_type=NodeType.IAM_USER, name="u")]
    for r in ("r1", "r2", "r3"):
        ents.append(Entity(entity_id=r, entity_type=NodeType.IAM_ROLE, name=r))
    ents.append(Entity(entity_id="b", entity_type=NodeType.S3_BUCKET, name="b", criticality=Criticality.CRITICAL))
    ents.append(Entity(entity_id="b2", entity_type=NodeType.S3_BUCKET, name="b2", criticality=Criticality.HIGH))
    def e(s, t, rel):
        return Relationship(source_id=s, target_id=t, relation_type=rel, status=EdgeStatus.CONFIRMED)
    A, R = RelationType.CAN_ASSUME, RelationType.CAN_READ
    edges = [e("u", "r1", A), e("r1", "r2", A), e("r2", "b", R), e("r2", "b2", R),
             e("u", "r3", A), e("r3", "b", R)]
    return GraphSnapshot(version="v1", created_at=NOW, entities=tuple(ents), edges=tuple(edges))


def cand_for(snap, src, dst):
    paths = find_paths(snap)
    edge = next(x.edge_id for x in snap.edges if x.source_id == src and x.target_id == dst)
    return next(c for c in generate_candidates(paths, snap) if c.plan.removed_edge_ids == (edge,))


def test_shared_root_cause_covers_multiple_paths():
    s = build()
    c = cand_for(s, "r1", "r2")          # r1->r2 feeds both the b and b2 paths
    assert len(c.covered_path_ids) == 2


def test_fix_blocks_paths_but_alternate_route_remains_visible():
    s = build()
    rec = recommend(cand_for(s, "r2", "b"), s, find_paths)
    assert len(rec.expected_blocked_path_ids) == 1       # u-r1-r2-b
    assert len(rec.residual_path_ids) == 2               # u-r1-r2-b2 and u-r3-b still exist
    assert rec.verification_status == "SIMULATED"        # never VERIFIED from P4


def test_shared_fix_blocks_more_and_reduces_more_risk():
    s = build()
    shared = recommend(cand_for(s, "r1", "r2"), s, find_paths)
    narrow = recommend(cand_for(s, "r2", "b"), s, find_paths)
    assert len(shared.expected_blocked_path_ids) == 2
    assert shared.estimated_risk_reduction > narrow.estimated_risk_reduction


def test_simulation_does_not_mutate_source_snapshot():
    s = build()
    before = s.model_dump_json()
    c = cand_for(s, "u", "r1")
    result, _ = simulate_plan(s, c.plan, find_paths)
    assert s.model_dump_json() == before and result.after_version != result.before_version


def test_blocking_everything_leaves_no_residual():
    s = build()
    r1 = cand_for(s, "u", "r1"); r3 = cand_for(s, "u", "r3")
    from contracts import RemediationPlan
    plan = RemediationPlan(id="both", base_version="v1",
                           removed_edge_ids=r1.plan.removed_edge_ids + r3.plan.removed_edge_ids)
    result, residual = simulate_plan(s, plan, find_paths)
    assert residual == [] and len(result.blocked_path_ids) == 3