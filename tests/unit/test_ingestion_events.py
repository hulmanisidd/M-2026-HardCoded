"""Checks the emitted events against the rules P2's repository enforces.

These tests do not import P2's updater. They re-state its rules (ordering,
payload shapes, edge ids, accepted statuses, source/scope match, strictly
newer timestamps) so we catch a mismatch before integration.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.ingestion import events as ev
from backend.ingestion.collector import CollectionError
from backend.ingestion.edges import build_edges
from backend.ingestion.events import (
    SOURCE_API,
    collect_events,
    collection_failed_event,
    emit_collection_events,
)
from backend.ingestion.loader import load_account_file, parse_account
from backend.ingestion.normalizer import normalize_entities
from backend.ingestion.snapshot import build_snapshot
from contracts.entities import Entity
from contracts.graph import GraphSnapshot
from contracts.relationships import EdgeStatus, Relationship, make_edge_id

ORG = Path(__file__).resolve().parents[2] / "fixtures" / "organization"
S1 = ORG / "scenario_01_passrole_escalation.json"
ACCT = "111122223333"
T0 = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(hours=1)


def parts(path=S1):
    account = load_account_file(path)
    return normalize_entities(account), build_edges(account).edges


def run(path=S1, **kw):
    entities, edges = parts(path)
    return emit_collection_events(entities, edges, account_id=ACCT, occurred_at=T0, **kw)


def of(events, kind):
    return [e for e in events if e.event_type == kind]


# ---- shape and order --------------------------------------------------------

def test_counts_for_scenario_1():
    events = run()
    assert len(of(events, ev.ENTITY_UPSERTED)) == 8
    assert len(of(events, ev.EDGE_OBSERVED)) == 14
    assert len(of(events, ev.COLLECTION_COMPLETED)) == 1
    assert len(events) == 23


def test_entities_before_edges_and_completed_last():
    kinds = [e.event_type for e in run()]
    last_entity = max(i for i, k in enumerate(kinds) if k == ev.ENTITY_UPSERTED)
    first_edge = min(i for i, k in enumerate(kinds) if k == ev.EDGE_OBSERVED)
    assert last_entity < first_edge
    assert kinds[-1] == ev.COLLECTION_COMPLETED


def test_every_edge_endpoint_was_upserted_earlier():
    seen = set()
    for e in run():
        if e.event_type == ev.ENTITY_UPSERTED:
            seen.add(e.payload["entity"]["entity_id"])
        elif e.event_type == ev.EDGE_OBSERVED:
            edge = e.payload["edge"]
            assert edge["source_id"] in seen and edge["target_id"] in seen


def test_payloads_round_trip_into_the_contract_models():
    entities, edges = parts()
    events = run()
    assert [Entity(**e.payload["entity"]) for e in of(events, ev.ENTITY_UPSERTED)] == list(entities)
    assert [Relationship(**e.payload["edge"]) for e in of(events, ev.EDGE_OBSERVED)] == list(edges)


def test_edge_ids_match_make_edge_id_and_statuses_are_accepted():
    for e in of(run(), ev.EDGE_OBSERVED):
        edge = e.payload["edge"]
        assert edge["edge_id"] == make_edge_id(edge["source_id"], edge["relation_type"],
                                               edge["target_id"], edge["discriminator"])
        assert edge["status"] in ("confirmed", "inferred")


def test_edge_events_carry_evidence_and_endpoints():
    for e in of(run(), ev.EDGE_OBSERVED):
        assert e.evidence_ids == tuple(e.payload["edge"]["evidence_ids"])
        assert e.entity_ids == tuple(dict.fromkeys((e.actor_id, e.target_id)))


def test_source_is_the_api_name_everywhere():
    events = run()
    assert {e.source for e in events} == {SOURCE_API}
    done = of(events, ev.COLLECTION_COMPLETED)[0]
    assert done.payload["scope"] == {"account_id": ACCT, "source_api": SOURCE_API}


def test_events_are_json_serializable():
    json.dumps([e.model_dump(mode="json") for e in run()])


def test_event_ids_are_unique_and_deterministic():
    a, b = run(), run()
    ids = [e.event_id for e in a]
    assert len(ids) == len(set(ids))
    assert ids == [e.event_id for e in b]


def test_event_ids_change_between_runs():
    entities, edges = parts()
    later = emit_collection_events(entities, edges, account_id=ACCT, occurred_at=T1)
    assert not {e.event_id for e in run()} & {e.event_id for e in later}


# ---- replaying events gives the same graph ----------------------------------

def test_replaying_events_rebuilds_the_same_graph():
    entities, edges = {}, {}
    for e in run():
        if e.event_type == ev.ENTITY_UPSERTED:
            entity = Entity(**e.payload["entity"])
            entities[entity.entity_id] = entity
        elif e.event_type == ev.EDGE_OBSERVED:
            edge = Relationship(**e.payload["edge"])
            edges[edge.edge_id] = edge
    rebuilt = GraphSnapshot(version="x", created_at=T0, entities=tuple(entities.values()),
                            edges=tuple(edges.values()))
    direct = build_snapshot(load_account_file(S1), created_at=T0).snapshot
    assert {e.entity_id for e in rebuilt.entities} == {e.entity_id for e in direct.entities}
    assert {e.edge_id for e in rebuilt.edges} == {e.edge_id for e in direct.edges}


# ---- freshness guard --------------------------------------------------------

def test_recollection_must_be_strictly_later():
    entities, edges = parts()
    with pytest.raises(ValueError, match="strictly later"):
        emit_collection_events(entities, edges, account_id=ACCT, occurred_at=T0, after=T0)
    with pytest.raises(ValueError, match="strictly later"):
        emit_collection_events(entities, edges, account_id=ACCT, occurred_at=T0, after=T1)
    assert emit_collection_events(entities, edges, account_id=ACCT, occurred_at=T1, after=T0)


def test_naive_timestamps_are_rejected():
    entities, edges = parts()
    with pytest.raises(Exception):
        emit_collection_events(entities, edges, account_id=ACCT, occurred_at=datetime(2026, 1, 1))


# ---- validation of what we emit ---------------------------------------------

def test_edge_with_unaccepted_status_is_refused():
    entities, edges = parts()
    bad = Relationship(source_id=edges[0].source_id, target_id=edges[0].target_id,
                       relation_type=edges[0].relation_type, status=EdgeStatus.UNKNOWN,
                       discriminator="x")
    with pytest.raises(ValueError, match="confirmed or inferred"):
        emit_collection_events(entities, (bad,), account_id=ACCT, occurred_at=T0)


def test_edge_with_missing_endpoint_is_refused():
    entities, edges = parts()
    with pytest.raises(ValueError, match="not being upserted"):
        emit_collection_events(entities[:1], edges, account_id=ACCT, occurred_at=T0)


def test_edge_with_wrong_id_is_refused():
    entities, edges = parts()
    wrong = Relationship(edge_id="e_wrong", source_id=edges[0].source_id,
                         target_id=edges[0].target_id, relation_type=edges[0].relation_type,
                         status=EdgeStatus.INFERRED)
    with pytest.raises(ValueError, match="make_edge_id"):
        emit_collection_events(entities, (wrong,), account_id=ACCT, occurred_at=T0)


# ---- removals ---------------------------------------------------------------

def test_removed_edges_and_entities_are_emitted_from_the_diff():
    first = build_snapshot(load_account_file(S1), created_at=T0).snapshot
    entities, edges = parts()
    gone_edge = edges[0]
    kept_edges = tuple(e for e in edges if e is not gone_edge)
    events = emit_collection_events(entities, kept_edges, account_id=ACCT, occurred_at=T1,
                                    previous=first, after=T0)
    removed = of(events, ev.EDGE_REMOVED)
    assert len(removed) == 1
    assert removed[0].payload == {
        "edge_id": gone_edge.edge_id, "source_id": gone_edge.source_id,
        "target_id": gone_edge.target_id, "relation_type": str(gone_edge.relation_type),
        "discriminator": gone_edge.discriminator,
    }
    assert events[-1].event_type == ev.COLLECTION_COMPLETED
    assert not of(events, ev.ENTITY_REMOVED)  # no entity actually vanished


def test_vanished_entity_emits_entity_removed():
    first = build_snapshot(load_account_file(S1), created_at=T0).snapshot
    entities, _ = parts()
    bob = next(e for e in entities if e.name == "bob")
    events = emit_collection_events(
        tuple(e for e in entities if e is not bob),
        tuple(e for e in first.edges if bob.entity_id not in (e.source_id, e.target_id)),
        account_id=ACCT, occurred_at=T1, previous=first)
    assert [e.payload for e in of(events, ev.ENTITY_REMOVED)] == [{"entity_id": bob.entity_id}]


def test_no_removals_without_previous():
    assert not of(run(), ev.EDGE_REMOVED) and not of(run(), ev.ENTITY_REMOVED)


# ---- failure ----------------------------------------------------------------

def test_collection_failed_event_shape():
    event = collection_failed_event(account_id=ACCT, occurred_at=T0, reason="Access denied")
    assert event.event_type == ev.COLLECTION_FAILED
    assert event.source == SOURCE_API
    assert event.payload == {"scope": {"account_id": ACCT, "source_api": SOURCE_API}}
    assert event.attributes == {"reason": "Access denied"}


def test_failed_scope_matches_edge_source_so_edges_can_go_unknown():
    failed = collection_failed_event(account_id=ACCT, occurred_at=T1, reason="x")
    edge_sources = {e.source for e in of(run(), ev.EDGE_OBSERVED)}
    assert edge_sources == {failed.payload["scope"]["source_api"]}


# ---- collect_events ---------------------------------------------------------

def test_collect_events_success_with_a_stub_collector():
    data = json.loads(S1.read_text())
    events = collect_events(ACCT, T0, collect=lambda: data)
    assert len(events) == 23 and events[-1].event_type == ev.COLLECTION_COMPLETED


def test_collect_events_turns_failure_into_collection_failed():
    def boom():
        raise CollectionError("No AWS credentials found.")
    events = collect_events(ACCT, T0, collect=boom)
    assert [e.event_type for e in events] == [ev.COLLECTION_FAILED]
    assert "credentials" in events[0].attributes["reason"]


def test_collect_events_refuses_data_from_another_account():
    data = json.loads(S1.read_text())
    with pytest.raises(ValueError, match="not 999988887777"):
        collect_events("999988887777", T0, collect=lambda: data)


def test_collect_events_passes_kwargs_to_the_collector():
    seen = {}
    def fake(**kw):
        seen.update(kw)
        return {}
    collect_events(ACCT, T0, collect=fake, profile="ro", include_aws_managed=False)
    assert seen == {"profile": "ro", "include_aws_managed": False}


def test_empty_account_gives_only_completed():
    events = collect_events(ACCT, T0, collect=lambda: {})
    assert [e.event_type for e in events] == [ev.COLLECTION_COMPLETED]
