import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone

from contracts import EdgeStatus, Entity, GraphSnapshot, Relationship

from .models import ChangeKind, GraphChange
from .repository import GraphRepository


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class InMemoryGraphRepository(GraphRepository):
    def __init__(self, clock: Callable[[], datetime] = _utc_now) -> None:
        self._clock = clock
        self._entities: dict[str, Entity] = {}
        self._edges: dict[str, Relationship] = {}

    # ---- versioning -------------------------------------------------
    def _time_blocked_ids(self, at: datetime) -> list[str]:
        """Edges whose validity window excludes `at` (mirrors check_transition)."""
        return sorted(
            e.edge_id
            for e in self._edges.values()
            if (e.valid_from and at < e.valid_from)
            or (e.valid_until and at >= e.valid_until)
        )

    def _hash(self, time_blocked: list[str]) -> str:
        payload = {
            "entities": [
                self._entities[k].model_dump(mode="json")
                for k in sorted(self._entities)
            ],
            "edges": [
                self._edges[k].model_dump(mode="json")
                for k in sorted(self._edges)
            ],
            "time_blocked": time_blocked,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "g_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    def _version(self, at: datetime | None = None) -> str:
        """Content + which edges are time-blocked at `at`.

        Same content and same time-effective state -> same version, so it is
        stable across wall-clock time until an edge window boundary is crossed.
        """
        at = at or self._clock()
        return self._hash(self._time_blocked_ids(at))

    def _change(self, kind: ChangeKind, subject_id: str, changed: bool) -> GraphChange:
        return GraphChange(
            kind=kind, subject_id=subject_id, changed=changed, version=self._version()
        )

    # ---- writes -----------------------------------------------------
    def upsert_entity(self, entity: Entity) -> GraphChange:
        existing = self._entities.get(entity.entity_id)
        if existing == entity:
            return self._change(ChangeKind.ENTITY_UPDATED, entity.entity_id, False)
        self._entities[entity.entity_id] = entity
        kind = ChangeKind.ENTITY_ADDED if existing is None else ChangeKind.ENTITY_UPDATED
        return self._change(kind, entity.entity_id, True)

    def upsert_edge(self, edge: Relationship) -> GraphChange:
        for endpoint in (edge.source_id, edge.target_id):
            if endpoint not in self._entities:
                raise ValueError(f"unknown entity {endpoint!r} for edge {edge.edge_id}")
        existing = self._edges.get(edge.edge_id)
        if existing == edge:
            return self._change(ChangeKind.EDGE_UPDATED, edge.edge_id, False)
        self._edges[edge.edge_id] = edge
        kind = ChangeKind.EDGE_ADDED if existing is None else ChangeKind.EDGE_UPDATED
        return self._change(kind, edge.edge_id, True)

    def invalidate_edge(self, edge_id: str) -> GraphChange:
        edge = self._edges[edge_id]  # KeyError if unknown
        if edge.status == EdgeStatus.INVALIDATED:
            return self._change(ChangeKind.EDGE_INVALIDATED, edge_id, False)
        self._edges[edge_id] = edge.model_copy(
            update={"status": EdgeStatus.INVALIDATED}
        )
        return self._change(ChangeKind.EDGE_INVALIDATED, edge_id, True)

    # ---- reads ------------------------------------------------------
    def get_entity(self, entity_id: str) -> Entity | None:
        return self._entities.get(entity_id)

    def get_edge(self, edge_id: str) -> Relationship | None:
        return self._edges.get(edge_id)

    def get_neighbors(self, entity_id: str) -> list[Relationship]:
        return sorted(
            (e for e in self._edges.values() if e.source_id == entity_id),
            key=lambda e: e.edge_id,
        )

    def snapshot(self) -> GraphSnapshot:
        created_at = self._clock()  # read once; version and created_at agree
        return GraphSnapshot(
            version=self._version(created_at),
            created_at=created_at,
            entities=tuple(self._entities[k] for k in sorted(self._entities)),
            edges=tuple(self._edges[k] for k in sorted(self._edges)),
        )