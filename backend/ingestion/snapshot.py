"""One call from raw IAM data to a versioned contracts.GraphSnapshot.

    raw account -> entities (normalizer) -> edges (edges) -> GraphSnapshot

This is the public entry point other modules should use. They never need
to import the normalizer or the edge builder directly.
"""
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from contracts.graph import GraphSnapshot
from contracts.relationships import EdgeStatus

from .edges import build_edges
from .loader import load_account_file
from .normalizer import normalize_entities
from .raw_models import RawIamAccount


@dataclass(frozen=True)
class SnapshotBuildResult:
    snapshot: GraphSnapshot
    warnings: tuple[str, ...] = ()


def _content_version(entities, edges) -> str:
    """Same data -> same version string, so snapshots can be compared and cached."""
    payload = json.dumps(
        {
            "entities": [e.model_dump(mode="json") for e in entities],
            "edges": [e.model_dump(mode="json") for e in edges],
        },
        sort_keys=True,
    )
    return "ing-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def build_snapshot(
    account: RawIamAccount,
    *,
    created_at: datetime | None = None,
    version: str | None = None,
    policy_edge_status: EdgeStatus = EdgeStatus.INFERRED,
) -> SnapshotBuildResult:
    """Build the graph snapshot for one account.

    Pass `created_at` for reproducible output (tests, benchmarks). Edge
    validity windows are judged against it, so it should be when the data
    was collected, not when the code ran.
    """
    entities = normalize_entities(account)
    built = build_edges(account, policy_edge_status=policy_edge_status)
    snapshot = GraphSnapshot(
        version=version or _content_version(entities, built.edges),
        created_at=created_at or datetime.now(timezone.utc),
        entities=entities,
        edges=built.edges,
    )
    return SnapshotBuildResult(snapshot=snapshot, warnings=built.warnings)


def build_snapshot_from_file(path: str | Path, **options) -> SnapshotBuildResult:
    return build_snapshot(load_account_file(path), **options)
