"""Synthetic org for demos and tests. Owner: P2.

The EXPECTED_PATHS fixture below was written by hand from the topology,
before any code enumerated paths. Tests check the graph against it, not the
other way round.

IMPORTANT: expiry is judged against snapshot.created_at. Build the repo with
clock=lambda: SEED_NOW, or the expired edge's result depends on wall time.

Topology (E = edge key):

  alice (user) --E1--> dev-role --E3--> ops-role --E4(pass)--> etl-role --E5--> customer-data (S3, critical)
  web-server --E2(STALE)--> dev-role                                   \\--E6--> db-creds (secret, critical)
  dev-role --E7--> deploy-role --E8(pass)--> etl-role
  deploy-role --E10(UNKNOWN)--> db-creds
  vendor (external, acct 2222) --E9(conditional)--> deploy-role
  dev-role --E11(EXPIRED)--> break-glass-role --E12--> customer-data
  dev-role --E13--> dev-scratch (S3, low)   [noise, not a target]
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from contracts import (
    Criticality,
    EdgeStatus,
    Entity,
    GraphSnapshot,
    NodeType,
    RelationType,
    Relationship,
    make_path_id,
)

SEED_NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
ACCT = "111111111111"
PARTNER_ACCT = "222222222222"

ENTRY_KEYS = ("alice", "web-server", "vendor")
TARGET_KEYS = ("customer-data", "db-creds")

# --- entities: key -> (id, type, name, criticality, account) ---------------
_ENTITIES = {
    "alice": (f"arn:aws:iam::{ACCT}:user/alice", NodeType.IAM_USER, "alice", Criticality.LOW, ACCT),
    "web-server": (f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-0web", NodeType.EC2_INSTANCE, "web-server", Criticality.MEDIUM, ACCT),
    "vendor": (f"arn:aws:iam::{PARTNER_ACCT}:root", NodeType.EXTERNAL_PRINCIPAL, "partner-vendor", Criticality.LOW, PARTNER_ACCT),
    "dev-role": (f"arn:aws:iam::{ACCT}:role/dev-role", NodeType.IAM_ROLE, "dev-role", Criticality.MEDIUM, ACCT),
    "ops-role": (f"arn:aws:iam::{ACCT}:role/ops-role", NodeType.IAM_ROLE, "ops-role", Criticality.HIGH, ACCT),
    "deploy-role": (f"arn:aws:iam::{ACCT}:role/deploy-role", NodeType.IAM_ROLE, "deploy-role", Criticality.HIGH, ACCT),
    "etl-role": (f"arn:aws:iam::{ACCT}:role/etl-role", NodeType.IAM_ROLE, "etl-role", Criticality.HIGH, ACCT),
    "break-glass": (f"arn:aws:iam::{ACCT}:role/break-glass-role", NodeType.IAM_ROLE, "break-glass-role", Criticality.CRITICAL, ACCT),
    "customer-data": ("arn:aws:s3:::customer-data", NodeType.S3_BUCKET, "customer-data", Criticality.CRITICAL, ACCT),
    "dev-scratch": ("arn:aws:s3:::dev-scratch", NodeType.S3_BUCKET, "dev-scratch", Criticality.LOW, ACCT),
    "db-creds": (f"arn:aws:secretsmanager:us-east-1:{ACCT}:secret:db-creds", NodeType.SECRET, "db-creds", Criticality.CRITICAL, ACCT),
}

R = RelationType
S = EdgeStatus
_PAST_FROM = datetime(2026, 8, 1, tzinfo=timezone.utc)
_PAST_UNTIL = datetime(2026, 9, 1, tzinfo=timezone.utc)

# --- edges: key -> (src, relation, dst, status, extra kwargs) --------------
_EDGES = {
    "E1": ("alice", R.CAN_ASSUME, "dev-role", S.CONFIRMED, {}),
    "E2": ("web-server", R.RUNS_AS, "dev-role", S.STALE, {}),
    "E3": ("dev-role", R.CAN_ASSUME, "ops-role", S.CONFIRMED, {}),
    "E4": ("ops-role", R.CAN_PASS_ROLE, "etl-role", S.CONFIRMED, {}),
    "E5": ("etl-role", R.CAN_READ, "customer-data", S.CONFIRMED, {}),
    "E6": ("etl-role", R.CAN_READ, "db-creds", S.CONFIRMED, {}),
    "E7": ("dev-role", R.CAN_ASSUME, "deploy-role", S.CONFIRMED, {}),
    "E8": ("deploy-role", R.CAN_PASS_ROLE, "etl-role", S.CONFIRMED, {}),
    "E9": ("vendor", R.CAN_ASSUME, "deploy-role", S.CONFIRMED,
           {"conditions": {"sts:ExternalId": "required"}}),
    "E10": ("deploy-role", R.CAN_READ, "db-creds", S.UNKNOWN, {}),
    "E11": ("dev-role", R.CAN_ASSUME, "break-glass", S.CONFIRMED,
            {"valid_from": _PAST_FROM, "valid_until": _PAST_UNTIL}),
    "E12": ("break-glass", R.CAN_READ, "customer-data", S.CONFIRMED, {}),
    "E13": ("dev-role", R.CAN_READ, "dev-scratch", S.CONFIRMED, {}),
}

# --- EXPECTED FIXTURE (hand-written first) ---------------------------------
# Each path: (edge keys in order, expected feasibility string).
# Rule: any blocked edge -> blocked; else any stale/unknown/inferred/conditions
# -> conditional; else feasible_under_model. A path is a possibility, not proof.
F, C, B = "feasible_under_model", "conditional", "blocked"
EXPECTED_PATHS: tuple[tuple[tuple[str, ...], str], ...] = (
    # alice
    (("E1", "E3", "E4", "E5"), F),
    (("E1", "E3", "E4", "E6"), F),
    (("E1", "E7", "E8", "E5"), F),
    (("E1", "E7", "E8", "E6"), F),
    (("E1", "E7", "E10"), C),        # E10 unknown
    (("E1", "E11", "E12"), B),       # E11 expired
    # web-server (E2 stale -> everything downstream is at best conditional)
    (("E2", "E3", "E4", "E5"), C),
    (("E2", "E3", "E4", "E6"), C),
    (("E2", "E7", "E8", "E5"), C),
    (("E2", "E7", "E8", "E6"), C),
    (("E2", "E7", "E10"), C),
    (("E2", "E11", "E12"), B),
    # vendor (E9 has unresolved conditions)
    (("E9", "E8", "E5"), C),
    (("E9", "E8", "E6"), C),
    (("E9", "E10"), C),
)
EXPECTED_BLOCKED_COUNT = 2
EXPECTED_NON_BLOCKED_COUNT = 13


# --- builders --------------------------------------------------------------
@dataclass(frozen=True)
class SeedData:
    entities: tuple[Entity, ...]
    edges: tuple[Relationship, ...]
    edge_ids: dict[str, str]      # edge key -> edge_id
    entity_ids: dict[str, str]    # entity key -> entity_id

    def expected_paths(self) -> dict[str, str]:
        """path_id -> expected feasibility, resolved against real edge ids."""
        out: dict[str, str] = {}
        for keys, status in EXPECTED_PATHS:
            out[make_path_id(tuple(self.edge_ids[k] for k in keys))] = status
        return out


def build_seed() -> SeedData:
    entity_ids = {k: v[0] for k, v in _ENTITIES.items()}
    entities = tuple(
        Entity(entity_id=eid, entity_type=t, name=n, criticality=c, account_id=a)
        for eid, t, n, c, a in _ENTITIES.values()
    )
    edges, edge_ids = [], {}
    for key, (src, rel, dst, status, extra) in _EDGES.items():
        edge = Relationship(
            source_id=entity_ids[src],
            target_id=entity_ids[dst],
            relation_type=rel,
            status=status,
            evidence_ids=(f"ev_seed_{key}",),
            **extra,
        )
        edges.append(edge)
        edge_ids[key] = edge.edge_id
    return SeedData(entities, tuple(edges), edge_ids, entity_ids)


def to_snapshot(seed: SeedData | None = None, version: str = "seed") -> GraphSnapshot:
    """Snapshot built directly from contracts (bypasses the repository)."""
    seed = seed or build_seed()
    return GraphSnapshot(
        version=version, created_at=SEED_NOW,
        entities=seed.entities, edges=seed.edges,
    )


def load_into(repo, seed: SeedData | None = None) -> SeedData:
    """Load via the repository interface (entities first, then edges)."""
    seed = seed or build_seed()
    for entity in seed.entities:
        repo.upsert_entity(entity)
    for edge in seed.edges:
        repo.upsert_edge(edge)
    return seed