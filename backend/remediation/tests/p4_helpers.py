from datetime import datetime, timezone

from contracts import (
    AttackPath, Criticality, EdgeStatus, Entity, FeasibilityStatus, GraphSnapshot,
    NodeType, RelationType, Relationship, make_path_id,
)
from backend.remediation.candidates import generate_candidates

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