"""Turns P1's NormalizedEvents into repository writes. Owner: P2.

Rules (agreed with P1):
- event.occurred_at is the observation time; the repository ignores anything
  not strictly newer than what it already holds, so delivery order is
  irrelevant (at-least-once, unordered).
- P1 only sends confirmed/inferred edges. stale, unknown and invalidated are
  ours: stale comes from the freshness window at snapshot time, unknown from
  COLLECTION_FAILED, invalidated from EDGE_REMOVED. A missing edge is never safe.
- edge_id is recomputed here; a mismatch rejects the event.

Errors: RejectedEvent = bad event, do not retry. MissingEndpointError (a
RejectedEvent) = an endpoint entity has not arrived yet; requeue and retry.
"""
from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Any, get_args

from pydantic import ValidationError

from contracts import (
    EdgeStatus,
    Entity,
    NormalizedEvent,
    Relationship,
    make_edge_id,
)

from .models import ChangeKind, GraphChange, Scope
from .repository import GraphRepository

try:  # lands with P1's contract PR
    from contracts.vocab import EventType  # type: ignore[attr-defined]
except ImportError:

    class EventType(StrEnum):  # local stand-in, same values as P1's enum
        ENTITY_UPSERTED = "ENTITY_UPSERTED"
        ENTITY_REMOVED = "ENTITY_REMOVED"
        EDGE_OBSERVED = "EDGE_OBSERVED"
        EDGE_REMOVED = "EDGE_REMOVED"
        COLLECTION_COMPLETED = "COLLECTION_COMPLETED"
        COLLECTION_FAILED = "COLLECTION_FAILED"


class RejectedEvent(ValueError):
    """The event is malformed or violates the agreed rules. Do not retry."""


class MissingEndpointError(RejectedEvent):
    """An edge endpoint is not in the graph yet. Requeue and retry later."""


def _criticality_nullable() -> bool:
    ann = Entity.model_fields["criticality"].annotation
    return type(None) in get_args(ann)


def _require(payload: dict[str, Any], key: str, typ: type) -> Any:
    value = payload.get(key)
    if not isinstance(value, typ):
        raise RejectedEvent(f"payload.{key} missing or not a {typ.__name__}")
    return value


def _scope(payload: dict[str, Any]) -> Scope:
    raw = _require(payload, "scope", dict)
    account, api = raw.get("account_id"), raw.get("source_api")
    if not (isinstance(account, str) and account and isinstance(api, str) and api):
        raise RejectedEvent("payload.scope needs account_id and source_api")
    return Scope(account, api)


class GraphUpdater:
    def __init__(self, repo: GraphRepository) -> None:
        self._repo = repo
        self._handlers: dict[str, Callable[[NormalizedEvent], GraphChange]] = {
            EventType.ENTITY_UPSERTED: self._entity_upserted,
            EventType.ENTITY_REMOVED: self._entity_removed,
            EventType.EDGE_OBSERVED: self._edge_observed,
            EventType.EDGE_REMOVED: self._edge_removed,
            EventType.COLLECTION_COMPLETED: self._collection_completed,
            EventType.COLLECTION_FAILED: self._collection_failed,
        }

    def apply_event(self, event: NormalizedEvent) -> GraphChange:
        handler = self._handlers.get(event.event_type)
        if handler is None:
            raise RejectedEvent(f"unsupported event_type {event.event_type!r}")
        try:
            return handler(event)
        except ValidationError as exc:
            raise RejectedEvent(f"{event.event_id}: invalid payload: {exc}") from exc

    # ---- helpers ----------------------------------------------------
    def _version(self) -> str:
        return self._repo.snapshot().version

    def _need_endpoints(self, *ids: str) -> None:
        for entity_id in ids:
            if self._repo.get_entity(entity_id) is None:
                raise MissingEndpointError(f"entity {entity_id!r} not in graph yet")

    # ---- entities ---------------------------------------------------
    def _entity_upserted(self, event: NormalizedEvent) -> GraphChange:
        data = dict(_require(event.payload, "entity", dict))
        # P1 sends criticality=null for "unclassified". Until the contract
        # allows None, drop it so the model default applies (LOW).
        if data.get("criticality") is None and not _criticality_nullable():
            data.pop("criticality", None)
        entity = Entity.model_validate(data)
        return self._repo.upsert_entity(entity, observed_at=event.occurred_at)

    def _entity_removed(self, event: NormalizedEvent) -> GraphChange:
        entity_id = _require(event.payload, "entity_id", str)
        # Entity record is kept; every incident edge is invalidated by the
        # repository when the removal is newer than the edge's latest event.
        return self._repo.remove_entity(entity_id, at=event.occurred_at)
    # ---- edges ------------------------------------------------------
    def _edge_observed(self, event: NormalizedEvent) -> GraphChange:
        data = dict(_require(event.payload, "edge", dict))
        if "observed_at" not in Relationship.model_fields:
            data.pop("observed_at", None)  # contract PR pending; event time rules
        edge = Relationship.model_validate(data)
        expected = make_edge_id(
            edge.source_id, edge.relation_type, edge.target_id, edge.discriminator
        )
        if edge.edge_id != expected:
            raise RejectedEvent(f"edge_id mismatch: got {edge.edge_id}, expected {expected}")
        if edge.status not in (EdgeStatus.CONFIRMED, EdgeStatus.INFERRED):
            raise RejectedEvent(
                f"EDGE_OBSERVED may only carry confirmed/inferred, got {edge.status}"
            )
        self._need_endpoints(edge.source_id, edge.target_id)
        return self._repo.upsert_edge(
            edge, observed_at=event.occurred_at, source_api=event.source
        )

    def _edge_removed(self, event: NormalizedEvent) -> GraphChange:
        p = event.payload
        edge_id = _require(p, "edge_id", str)
        source_id = _require(p, "source_id", str)
        target_id = _require(p, "target_id", str)
        relation_type = _require(p, "relation_type", str)
        discriminator = p.get("discriminator", "")
        if not isinstance(discriminator, str):
            raise RejectedEvent("payload.discriminator must be a string")
        expected = make_edge_id(source_id, relation_type, target_id, discriminator)
        if edge_id != expected:
            raise RejectedEvent(f"edge_id mismatch: got {edge_id}, expected {expected}")

        if self._repo.get_edge(edge_id) is not None:
            return self._repo.invalidate_edge(edge_id, at=event.occurred_at)

        # Removal arrived before the edge it removes. Store an INVALIDATED
        # tombstone so the older observation, when it shows up, is ignored.
        self._need_endpoints(source_id, target_id)
        tombstone = Relationship(
            edge_id=edge_id,
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            discriminator=discriminator,
            status=EdgeStatus.INVALIDATED,
        )
        return self._repo.upsert_edge(
            tombstone, observed_at=event.occurred_at, source_api=event.source
        )

    # ---- collections ------------------------------------------------
    def _collection_completed(self, event: NormalizedEvent) -> GraphChange:
        scope = _scope(event.payload)
        # Nothing to write: UNKNOWN edges clear when P1 re-emits them as
        # EDGE_OBSERVED with a newer occurred_at. Edges it neither re-emits
        # nor removes stay UNKNOWN, which is the safe direction.
        return GraphChange(
            kind=ChangeKind.COLLECTION_COMPLETED,
            subject_id=scope.key,
            changed=False,
            version=self._version(),
        )

    def _collection_failed(self, event: NormalizedEvent) -> GraphChange:
        scope = _scope(event.payload)
        return self._repo.mark_scope_unknown(scope, at=event.occurred_at)
