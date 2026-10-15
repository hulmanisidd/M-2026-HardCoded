"""P4 candidate interventions.

A candidate = "remove these edges from the graph", expressed with the shared
`RemediationPlan` contract. Candidates are PROPOSALS only; P4 never changes a real
AWS account. Cost / disruption values are configurable assumptions, not measurements.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from contracts import (
    AttackPath,
    FeasibilityStatus,
    GraphSnapshot,
    RelationType,
    RemediationPlan,
)

# relation type -> (action_type, cost 0-1, operational disruption 0-1). ASSUMPTIONS: tune with the team.
DEFAULT_ACTIONS: dict[RelationType, tuple[str, float, float]] = {
    RelationType.CAN_ASSUME: ("restrict_role_trust", 0.3, 0.4),
    RelationType.CAN_PASS_ROLE: ("remove_pass_role", 0.3, 0.3),
    RelationType.CAN_MODIFY_POLICY: ("remove_policy_modification", 0.2, 0.2),
    RelationType.CAN_READ: ("remove_read_permission", 0.2, 0.5),
    RelationType.CAN_WRITE: ("remove_write_permission", 0.2, 0.6),
    RelationType.CAN_DECRYPT: ("remove_decrypt_permission", 0.2, 0.5),
    RelationType.CAN_INVOKE: ("remove_invoke_permission", 0.2, 0.5),
    RelationType.MEMBER_OF: ("remove_group_membership", 0.1, 0.3),
    RelationType.HAS_POLICY: ("detach_policy", 0.2, 0.4),
    RelationType.RUNS_AS: ("change_runtime_role", 0.4, 0.6),
}


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    action_type: str
    target_id: str                  # the edge's source principal (whose permission changes)
    plan: RemediationPlan
    cost: float                     # 0-1 assumption
    disruption: float               # 0-1 assumption
    covered_path_ids: tuple[str, ...]   # paths that use the removed edge(s) (upper bound on blocked)
    rationale: str
    assumptions: tuple[str, ...] = field(default_factory=tuple)


def generate_candidates(paths: list[AttackPath], snapshot: GraphSnapshot,
                        actions: dict | None = None) -> list[Candidate]:
    """One candidate per distinct edge that appears on at least one non-blocked path.

    An edge shared by several paths yields ONE candidate covering all of them
    (the shared root cause)."""
    table = actions or DEFAULT_ACTIONS
    live = [p for p in paths if p.feasibility_status != FeasibilityStatus.BLOCKED]
    by_edge: dict[str, list[str]] = {}
    for p in sorted(live, key=lambda p: p.path_id):
        for edge_id in p.edge_ids:
            by_edge.setdefault(edge_id, []).append(p.path_id)

    out: list[Candidate] = []
    for edge_id in sorted(by_edge):
        edge = snapshot.get_edge(edge_id)
        if edge is None or edge.relation_type not in table:
            continue
        action, cost, disruption = table[edge.relation_type]
        plan_id = "plan_" + hashlib.sha256(edge_id.encode()).hexdigest()[:12]
        out.append(Candidate(
            candidate_id=plan_id,
            action_type=action,
            target_id=edge.source_id,
            plan=RemediationPlan(
                id=plan_id, base_version=snapshot.version, removed_edge_ids=(edge_id,),
                rationale=f"{action}: {edge.source_id} -[{edge.relation_type.value}]-> {edge.target_id}",
            ),
            cost=cost,
            disruption=disruption,
            covered_path_ids=tuple(by_edge[edge_id]),
            rationale=f"edge {edge_id} is used by {len(by_edge[edge_id])} path(s)",
            assumptions=(f"cost={cost} and disruption={disruption} are configured assumptions",),
        ))
    return out