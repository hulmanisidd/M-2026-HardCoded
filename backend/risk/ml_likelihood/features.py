"""Feature extraction: (AttackPath, GraphSnapshot) -> numeric feature dict.

Rules:
  * Read-only. Uses only fields that already exist in `contracts/`.
  * Missing or untrustworthy evidence is NEVER replaced by a default value.
    If a required input is missing, `features` is None and `unknowns` says why.
    (Same philosophy as backend/remediation/scoring.py.)
  * Target criticality is a *target characteristic* used to model attacker
    behaviour. It is not the impact score; impact stays in P4's module.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from contracts import (
    AttackPath,
    Criticality,
    EdgeStatus,
    FeasibilityStatus,
    GraphSnapshot,
    NodeType,
    RelationType,
)

_CRIT_ORDINAL = {
    Criticality.LOW: 1.0,
    Criticality.MEDIUM: 2.0,
    Criticality.HIGH: 3.0,
    Criticality.CRITICAL: 4.0,
}

# Fixed order. A trained model is only valid for exactly this list.
FEATURE_NAMES: tuple[str, ...] = (
    ("hops",)
    + tuple(f"n_rel_{r.value}" for r in RelationType)
    + (
        "n_confirmed",
        "n_inferred",
        "n_stale",
        "n_conditioned",
        "frac_confirmed",
        "mean_evidence_per_edge",
        "path_evidence_count",
        "is_conditional_path",
        "target_criticality",
    )
    + tuple(f"target_is_{t.value}" for t in NodeType)
    + ("entry_is_external", "entry_is_user")
)


@dataclass(frozen=True)
class FeatureResult:
    path_id: str
    features: dict[str, float] | None
    unknowns: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.features is not None


def extract_features(path: AttackPath, snapshot: GraphSnapshot) -> FeatureResult:
    """Return features for one path, or features=None plus reasons if evidence is missing."""
    if not isinstance(path, AttackPath):
        raise TypeError(f"path must be AttackPath, got {type(path).__name__}")
    if not isinstance(snapshot, GraphSnapshot):
        raise TypeError(f"snapshot must be GraphSnapshot, got {type(snapshot).__name__}")

    unknowns: list[str] = []

    if path.feasibility_status == FeasibilityStatus.BLOCKED:
        unknowns.append("path is BLOCKED under the model; ML estimator is not defined for blocked paths")
    if path.graph_version != snapshot.version:
        unknowns.append(f"path computed on graph {path.graph_version}, snapshot is {snapshot.version}")

    target = snapshot.get_entity(path.target_node_id)
    entry = snapshot.get_entity(path.entry_node_id)
    if target is None:
        unknowns.append(f"target entity {path.target_node_id} not in snapshot")
    elif target.criticality is None:
        unknowns.append(f"target {target.name} has unknown criticality")
    if entry is None:
        unknowns.append(f"entry entity {path.entry_node_id} not in snapshot")

    edges = []
    for edge_id in path.edge_ids:
        edge = snapshot.get_edge(edge_id)
        if edge is None:
            unknowns.append(f"edge {edge_id} not in snapshot")
        elif edge.status == EdgeStatus.UNKNOWN:
            unknowns.append(f"edge {edge_id} has UNKNOWN status")
        elif edge.status == EdgeStatus.INVALIDATED:
            unknowns.append(f"edge {edge_id} is INVALIDATED")
        else:
            edges.append(edge)

    if unknowns:
        return FeatureResult(path.path_id, None, unknowns)

    hops = len(edges)
    feats: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
    feats["hops"] = float(hops)
    for e in edges:
        feats[f"n_rel_{e.relation_type.value}"] += 1.0
    feats["n_confirmed"] = float(sum(e.status == EdgeStatus.CONFIRMED for e in edges))
    feats["n_inferred"] = float(sum(e.status == EdgeStatus.INFERRED for e in edges))
    feats["n_stale"] = float(sum(e.status == EdgeStatus.STALE for e in edges))
    feats["n_conditioned"] = float(sum(bool(e.conditions) for e in edges))
    feats["frac_confirmed"] = feats["n_confirmed"] / hops
    feats["mean_evidence_per_edge"] = sum(len(e.evidence_ids) for e in edges) / hops
    feats["path_evidence_count"] = float(len(path.evidence_ids))
    feats["is_conditional_path"] = float(path.feasibility_status == FeasibilityStatus.CONDITIONAL)
    feats["target_criticality"] = _CRIT_ORDINAL[target.criticality]
    feats[f"target_is_{target.entity_type.value}"] = 1.0
    feats["entry_is_external"] = float(entry.entity_type == NodeType.EXTERNAL_PRINCIPAL)
    feats["entry_is_user"] = float(entry.entity_type == NodeType.IAM_USER)
    return FeatureResult(path.path_id, feats, [])