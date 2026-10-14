"""Turn an ingestion run into NormalizedEvents for P2's GraphUpdater.

    events = collect_events("111122223333", occurred_at)       # live collection
    events = emit_collection_events(entities, edges, ...)       # from data you already have
    for event in events:
        GraphUpdater(repo).apply_event(event)

Rules this module follows (from P2's repository spec):
  * Order: every ENTITY_UPSERTED first, then EDGE_OBSERVED (the repository
    needs both endpoints to exist), removals, and COLLECTION_COMPLETED last.
  * `source` is the API name, and it is the SAME string in the edge events and
    in scope.source_api, so COLLECTION_FAILED can find the edges to mark UNKNOWN.
  * `occurred_at` is the observation time. A re-collection MUST use a strictly
    later time than the previous run or the repository ignores it as a replay.
    Pass `after=` and we refuse to emit events that would be ignored.
  * Only CONFIRMED and INFERRED edges are accepted by the repository.
  * Edges missing from a later run are not removed automatically. Pass
    `previous=` (the last run's entities and edges) and we emit EDGE_REMOVED /
    ENTITY_REMOVED for the difference.
  * We never send STALE. The repository works that out when a snapshot is read.
  * Use the repository's snapshot().version downstream, not ours.
"""
import hashlib
from datetime import datetime
from typing import Any, Callable, Iterable

from contracts.entities import Entity
from contracts.events import NormalizedEvent
from contracts.relationships import EdgeStatus, Relationship, make_edge_id

from .collector import CollectionError, collect_account, detect_account_id
from .edges import build_edges
from .loader import parse_account
from .normalizer import normalize_entities

SOURCE_API = "iam:GetAccountAuthorizationDetails"

# Event type strings. P2's updater keeps a local stand-in enum until EventType
# lands in contracts/vocab.py; switch these to that enum when it does.
ENTITY_UPSERTED = "ENTITY_UPSERTED"
ENTITY_REMOVED = "ENTITY_REMOVED"
EDGE_OBSERVED = "EDGE_OBSERVED"
EDGE_REMOVED = "EDGE_REMOVED"
COLLECTION_COMPLETED = "COLLECTION_COMPLETED"
COLLECTION_FAILED = "COLLECTION_FAILED"

_ACCEPTED_STATUSES = {EdgeStatus.CONFIRMED, EdgeStatus.INFERRED}


def scope(account_id: str, source_api: str = SOURCE_API) -> dict[str, str]:
    return {"account_id": account_id, "source_api": source_api}


def _event_id(kind: str, source: str, occurred_at: datetime, key: str) -> str:
    raw = "\x1f".join([kind, source, occurred_at.isoformat(), key])
    return "ev_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _event(kind, source, occurred_at, key, payload, **fields) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=_event_id(kind, source, occurred_at, key),
        event_type=kind,
        source=source,
        occurred_at=occurred_at,
        payload=payload,
        **fields,
    )


def _check(entities: tuple[Entity, ...], edges: tuple[Relationship, ...]) -> None:
    known = {entity.entity_id for entity in entities}
    for edge in edges:
        if edge.status not in _ACCEPTED_STATUSES:
            raise ValueError(f"edge {edge.edge_id} has status {edge.status}; the repository only accepts confirmed or inferred")
        expected = make_edge_id(edge.source_id, str(edge.relation_type), edge.target_id, edge.discriminator)
        if edge.edge_id != expected:
            raise ValueError(f"edge {edge.edge_id} does not match make_edge_id(...)")
        if edge.source_id not in known or edge.target_id not in known:
            raise ValueError(f"edge {edge.edge_id} points at an entity that is not being upserted")


def emit_collection_events(
    entities: Iterable[Entity],
    edges: Iterable[Relationship],
    *,
    account_id: str,
    occurred_at: datetime,
    source_api: str = SOURCE_API,
    previous: Any = None,
    after: datetime | None = None,
) -> tuple[NormalizedEvent, ...]:
    """Events for one successful collection.

    `previous` is the last run's GraphSnapshot (or anything with `.entities`
    and `.edges`); it is only used to find what disappeared.
    """
    entities, edges = tuple(entities), tuple(edges)
    if after is not None and occurred_at <= after:
        raise ValueError(
            "occurred_at must be strictly later than the previous collection, "
            "otherwise the repository ignores these events as replays"
        )
    _check(entities, edges)

    events: list[NormalizedEvent] = []
    for entity in entities:
        events.append(_event(
            ENTITY_UPSERTED, source_api, occurred_at, entity.entity_id,
            {"entity": entity.model_dump(mode="json")},
            entity_ids=(entity.entity_id,),
        ))
    for edge in edges:
        events.append(_event(
            EDGE_OBSERVED, source_api, occurred_at, edge.edge_id,
            {"edge": edge.model_dump(mode="json")},
            actor_id=edge.source_id, target_id=edge.target_id,
            evidence_ids=edge.evidence_ids,
        ))

    if previous is not None:
        now_edges = {edge.edge_id for edge in edges}
        now_entities = {entity.entity_id for entity in entities}
        for old in previous.edges:
            if old.edge_id not in now_edges:
                events.append(_event(
                    EDGE_REMOVED, source_api, occurred_at, old.edge_id,
                    {
                        "edge_id": old.edge_id,
                        "source_id": old.source_id,
                        "target_id": old.target_id,
                        "relation_type": str(old.relation_type),
                        "discriminator": old.discriminator,
                    },
                    actor_id=old.source_id, target_id=old.target_id,
                ))
        for old in previous.entities:
            if old.entity_id not in now_entities:
                events.append(_event(
                    ENTITY_REMOVED, source_api, occurred_at, old.entity_id,
                    {"entity_id": old.entity_id},
                    entity_ids=(old.entity_id,),
                ))

    events.append(_event(
        COLLECTION_COMPLETED, source_api, occurred_at, account_id,
        {"scope": scope(account_id, source_api)},
    ))
    return tuple(events)


def collection_failed_event(
    *,
    account_id: str,
    occurred_at: datetime,
    reason: str,
    source_api: str = SOURCE_API,
) -> NormalizedEvent:
    """Tells the repository this source could not be read, so the edges it
    holds from this API and account become UNKNOWN instead of staying trusted."""
    return _event(
        COLLECTION_FAILED, source_api, occurred_at, account_id,
        {"scope": scope(account_id, source_api)},
        severity="error",
        attributes={"reason": reason},
    )


def collect_events(
    account_id: str,
    occurred_at: datetime,
    *,
    collect: Callable[..., dict] = collect_account,
    previous: Any = None,
    after: datetime | None = None,
    policy_edge_status: EdgeStatus = EdgeStatus.INFERRED,
    **collect_kwargs: Any,
) -> tuple[NormalizedEvent, ...]:
    """Collect from AWS and return the events: the full set on success, or a
    single COLLECTION_FAILED if collection could not complete.

    `account_id` is required up front because a failed collection has no data
    to read it from, and COLLECTION_FAILED needs it to find the right edges.
    """
    try:
        data = collect(**collect_kwargs)
    except CollectionError as error:
        return (collection_failed_event(account_id=account_id, occurred_at=occurred_at, reason=str(error)),)

    found = detect_account_id(data)
    if found is not None and found != account_id:
        raise ValueError(f"collected data is from account {found}, not {account_id}")

    account = parse_account(data)
    built = build_edges(account, policy_edge_status=policy_edge_status)
    return emit_collection_events(
        normalize_entities(account), built.edges,
        account_id=account_id, occurred_at=occurred_at, previous=previous, after=after,
    )
