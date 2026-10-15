
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.updater import GraphUpdater
from backend.ingestion.events import (
    SOURCE_API,
    collection_failed_event,
    emit_collection_events,
)
from backend.ingestion.snapshot import build_snapshot_from_file
from contracts import EdgeStatus


ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = sorted(
    (ROOT / "fixtures" / "organization").glob("scenario_*.json")
)
ACCOUNT_ID = "111122223333"
T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)


def apply_all(updater, events):
    return [updater.apply_event(event) for event in events]


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
def test_ingestion_events_update_repository(path):
    built = build_snapshot_from_file(path, created_at=T0)
    expected = built.snapshot

    # Keep the repository clock fixed so freshness is deterministic.
    repo = InMemoryGraphRepository(clock=lambda: T0)
    updater = GraphUpdater(repo)

    events = emit_collection_events(
        expected.entities,
        expected.edges,
        account_id=ACCOUNT_ID,
        occurred_at=T0,
    )
    apply_all(updater, events)

    actual = repo.snapshot()

    assert {e.entity_id for e in actual.entities} == {
        e.entity_id for e in expected.entities
    }
    assert {e.edge_id for e in actual.edges} == {
        e.edge_id for e in expected.edges
    }

    for edge in expected.edges:
        stored = repo.get_edge(edge.edge_id)
        assert stored is not None
        assert stored.source_id == edge.source_id
        assert stored.target_id == edge.target_id


def test_failed_collection_marks_observed_edges_unknown():
    built = build_snapshot_from_file(SCENARIOS[0], created_at=T0)
    snapshot = built.snapshot

    repo = InMemoryGraphRepository(clock=lambda: T0)
    updater = GraphUpdater(repo)

    events = emit_collection_events(
        snapshot.entities,
        snapshot.edges,
        account_id=ACCOUNT_ID,
        occurred_at=T0,
    )
    apply_all(updater, events)

    observed_edges = [
        edge for edge in snapshot.edges
        if edge.status in (EdgeStatus.CONFIRMED, EdgeStatus.INFERRED)
    ]
    assert observed_edges, "fixture should contain observed edges"

    failure = collection_failed_event(
        account_id=ACCOUNT_ID,
        occurred_at=T0 + timedelta(minutes=5),
        reason="synthetic collection failure",
        source_api=SOURCE_API,
    )
    updater.apply_event(failure)

    for edge in observed_edges:
        assert repo.get_edge(edge.edge_id).status == EdgeStatus.UNKNOWN

    # A newer successful observation should restore the original edge status.
    newer_events = emit_collection_events(
        snapshot.entities,
        snapshot.edges,
        account_id=ACCOUNT_ID,
        occurred_at=T0 + timedelta(minutes=10),
        after=T0,
    )
    apply_all(updater, newer_events)

    for edge in observed_edges:
        assert repo.get_edge(edge.edge_id).status == edge.status
