"""SYNTHETIC data generator. PROOF OF CONCEPT ONLY.

!! The labels produced here come from a hand-written generative process whose
!! coefficients are ASSUMPTIONS made by the team. They are not observed attack
!! outcomes. A model that fits this data has learned our assumptions back; it
!! says NOTHING about real-world exploitation probability.

What this data IS good for: exercising the pipeline end to end (feature
extraction, training, calibration checks, persistence, the P4 interface) so
that it can be re-run unchanged once real labels exist.

Target (label definition used throughout):
    y = 1  <=>  an attacker starting at path.entry_node_id, within the
                observation window, successfully reaches path.target_node_id
                using exactly this path.  y = 0 otherwise.
    (Window is nominally 30 days; in synthetic data it is only a convention.)

Paths are built as real AttackPath + GraphSnapshot objects and pushed through
the SAME `extract_features` used in production, so extraction code is exercised.

Deliberate imperfections, so the task is not trivially recoverable:
  * an unobserved per-sample noise term (attacker skill / luck),
  * one interaction (policy-edit edges matter less when they are conditioned),
  * one nonlinearity (diminishing returns past 3 hops).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np

from contracts import (
    AttackPath,
    Criticality,
    EdgeStatus,
    Entity,
    FeasibilityStatus,
    GraphSnapshot,
    NodeType,
    Relationship,
    RelationType,
    make_path_id,
)

from backend.remediation.scoring import assess_path  # read-only use, for comparison

from .features import FEATURE_NAMES, extract_features

GENERATOR_VERSION = "synthetic-v1"
SYNTHETIC_DISCLAIMER = (
    "SYNTHETIC proof-of-concept data. Labels come from assumed coefficients, "
    "not real attack outcomes. Not evidence of real-world attack probability."
)

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

# --- ASSUMED coefficients of the latent log-odds (team assumptions, not evidence) ---
ASSUMED = {
    "intercept": -0.2,
    "per_extra_hop": -0.55,
    "diminishing_after_3_hops": -0.4,
    "rel": {
        "can_assume": 0.25, "can_pass_role": 0.45, "can_modify_policy": 0.9,
        "runs_as": 0.1, "can_read": 0.2, "can_write": 0.2,
        "can_invoke": 0.1, "can_decrypt": -0.1,
    },
    "inferred_edge": -0.6,
    "stale_edge": -1.0,
    "conditioned_edge": -0.7,
    "modify_policy_x_conditioned": -0.5,   # interaction
    "per_evidence_id": 0.15,
    "external_entry": -0.3,
    "target_criticality_per_level": 0.25,  # centred at 2.5
    "noise_sd": 0.6,                       # unobserved factors
}

_MID_RELS = [RelationType.CAN_ASSUME, RelationType.CAN_PASS_ROLE,
             RelationType.CAN_MODIFY_POLICY, RelationType.RUNS_AS]
_FINAL = [
    (RelationType.CAN_READ, NodeType.S3_BUCKET),
    (RelationType.CAN_READ, NodeType.SECRET),
    (RelationType.CAN_WRITE, NodeType.S3_BUCKET),
    (RelationType.CAN_DECRYPT, NodeType.KMS_KEY),
    (RelationType.CAN_INVOKE, NodeType.LAMBDA_FUNCTION),
]
_ENTRY_TYPES = [NodeType.IAM_USER, NodeType.IAM_ROLE, NodeType.EC2_INSTANCE, NodeType.EXTERNAL_PRINCIPAL]
_CRITS = list(Criticality)


@dataclass(frozen=True)
class SyntheticDataset:
    X: np.ndarray               # (n, n_features), column order = feature_names
    y: np.ndarray               # (n,) int 0/1
    feature_names: tuple[str, ...]
    path_ids: tuple[str, ...]
    rule_scores: np.ndarray     # existing rule-based likelihood_score (P4), for comparison only
    meta: dict                  # seed, generator version, disclaimer, base rate


def _make_one(rng: np.random.Generator, idx: int, intercept_shift: float = 0.0) -> tuple[AttackPath, GraphSnapshot, float]:
    hops = int(rng.choice([1, 2, 3, 4, 5], p=[0.15, 0.3, 0.3, 0.15, 0.10]))
    entry_type = _ENTRY_TYPES[rng.integers(len(_ENTRY_TYPES))]
    final_rel, target_type = _FINAL[rng.integers(len(_FINAL))]
    crit = _CRITS[rng.integers(len(_CRITS))]

    ents = [Entity(entity_id=f"s{idx}_n0", entity_type=entry_type, name=f"entry{idx}")]
    for k in range(1, hops):
        ents.append(Entity(entity_id=f"s{idx}_n{k}", entity_type=NodeType.IAM_ROLE, name=f"role{idx}_{k}"))
    ents.append(Entity(entity_id=f"s{idx}_n{hops}", entity_type=target_type,
                       name=f"target{idx}", criticality=crit))

    edges, logit = [], ASSUMED["intercept"] + intercept_shift
    for k in range(hops):
        rel = final_rel if k == hops - 1 else _MID_RELS[rng.integers(len(_MID_RELS))]
        status = rng.choice([EdgeStatus.CONFIRMED, EdgeStatus.INFERRED, EdgeStatus.STALE], p=[0.6, 0.3, 0.1])
        conditioned = bool(rng.random() < 0.25)
        n_ev = int(rng.integers(1, 3)) if status == EdgeStatus.CONFIRMED else int(rng.integers(0, 2))
        edges.append(Relationship(
            source_id=ents[k].entity_id, target_id=ents[k + 1].entity_id, relation_type=rel,
            status=status, conditions={"aws:SourceIp": "10.0.0.0/8"} if conditioned else {},
            evidence_ids=tuple(f"ev_{idx}_{k}_{j}" for j in range(n_ev)),
        ))
        logit += ASSUMED["rel"].get(rel.value, 0.0)
        logit += {EdgeStatus.INFERRED: ASSUMED["inferred_edge"],
                  EdgeStatus.STALE: ASSUMED["stale_edge"]}.get(status, 0.0)
        if conditioned:
            logit += ASSUMED["conditioned_edge"]
            if rel == RelationType.CAN_MODIFY_POLICY:
                logit += ASSUMED["modify_policy_x_conditioned"]
        logit += ASSUMED["per_evidence_id"] * n_ev

    logit += ASSUMED["per_extra_hop"] * (hops - 1)
    if hops > 3:
        logit += ASSUMED["diminishing_after_3_hops"] * (hops - 3)
    if entry_type == NodeType.EXTERNAL_PRINCIPAL:
        logit += ASSUMED["external_entry"]
    logit += ASSUMED["target_criticality_per_level"] * ({"low": 1, "medium": 2, "high": 3, "critical": 4}[crit.value] - 2.5)
    logit += rng.normal(0.0, ASSUMED["noise_sd"])

    any_cond = any(e.conditions for e in edges) or any(e.status != EdgeStatus.CONFIRMED for e in edges)
    path = AttackPath(
        path_id=make_path_id(tuple(e.edge_id for e in edges)),
        graph_version="synthetic", entry_node_id=ents[0].entity_id, target_node_id=ents[-1].entity_id,
        node_ids=tuple(e.entity_id for e in ents), edge_ids=tuple(e.edge_id for e in edges),
        feasibility_status=FeasibilityStatus.CONDITIONAL if any_cond else FeasibilityStatus.FEASIBLE_UNDER_MODEL,
        evidence_ids=tuple(f"pev_{idx}_{j}" for j in range(int(rng.integers(0, 3)))),
    )
    snap = GraphSnapshot(version="synthetic", created_at=_NOW, entities=tuple(ents), edges=tuple(edges))
    return path, snap, logit


def generate_synthetic_dataset(n: int = 5000, seed: int = 0, intercept_shift: float = 0.0) -> SyntheticDataset:
    """Deterministic for a given (n, seed, intercept_shift).

    `intercept_shift` changes the overall base rate WITHOUT changing the feature
    relationships. It exists only to demonstrate how calibration degrades under
    prior shift (e.g. a different environment where exploitation is rarer/commoner).
    """
    if not isinstance(n, int) or n < 10:
        raise ValueError("n must be an int >= 10")
    rng = np.random.default_rng(seed)
    rows, ys, ids, rules = [], [], [], []
    for i in range(n):
        path, snap, logit = _make_one(rng, i, intercept_shift)
        res = extract_features(path, snap)
        assert res.ok, res.unknowns  # generator never emits unknown evidence
        rows.append([res.features[name] for name in FEATURE_NAMES])
        p = 1.0 / (1.0 + np.exp(-logit))
        ys.append(int(rng.random() < p))
        ids.append(f"{path.path_id}#{i}")
        rule = assess_path(path, snap).likelihood_score
        assert rule is not None
        rules.append(rule)
    y = np.array(ys, dtype=int)
    return SyntheticDataset(
        X=np.array(rows, dtype=float), y=y, feature_names=FEATURE_NAMES, path_ids=tuple(ids),
        rule_scores=np.array(rules, dtype=float),
        meta={"seed": seed, "intercept_shift": intercept_shift, "n": n, "generator_version": GENERATOR_VERSION,
              "base_rate": float(y.mean()), "disclaimer": SYNTHETIC_DISCLAIMER},
    )