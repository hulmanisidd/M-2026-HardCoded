import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from contracts import EdgeStatus, Entity, GraphSnapshot, Relationship

from .models import ChangeKind, GraphChange, Scope
from .repository import GraphRepository

# Placeholder until the team agrees a number. None disables staleness.
DEFAULT_FRESHNESS_WINDOW = timedelta(hours=24)

_FRESHNESS_APPLIES = (EdgeStatus.CONFIRMED, EdgeStatus.INFERRED)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class InMemoryGraphRepository(GraphRepository):
    def __init__(
        self,
        clock: Callable[[], datetime] = _utc_now,
        freshness_window: timedelta | None = DEFAULT_FRESHNESS_WINDOW,
    ) -> None:
        self._clock = clock
        self._window = freshness_window
        self._entities: dict[str, Entity] = {}
        self._edges: dict[str, Relationship] = {}
        self._entity_observed_at: dict[str, datetime] = {}
        # Event-time ledgers, per edge_id. Not part of the contract.
        self._observed_at: dict[str, datetime] = {}
        self._invalidated_at: dict[str, datetime] = {}
        self._unknown_since: dict[str, datetime] = {}
        self._source_api: dict[str, str] = {}

    # ---- event-time ledger ------------------------------------------
    def _latest_event_time(self, edge_id: str) -> datetime | None:
        times = [
            d[edge_id]
            for d in (self._observed_at, self._invalidated_at, self._unknown_since)
            if edge_id in d
        ]
        return max(times) if times else None

    # ---- versioning -------------------------------------------------
    def _time_blocked_ids(self, at: datetime) -> list[str]:
        """Edges whose validity window excludes `at` (mirrors check_transition)."""
        return sorted(
            e.edge_id
            for e in self._edges.values()
            if (e.valid_from and at < e.valid_from)
            or (e.valid_until and at >= e.valid_until)
        )

    def _is_stale(self, edge: Relationship, at: datetime) -> bool:
        if self._window is None or edge.status not in _FRESHNESS_APPLIES:
            return False
        seen = self._observed_at.get(edge.edge_id)
        # No observation time (seed / direct writes) -> freshness not judged.
        return seen is not None and at >= seen + self._window

    def _effective_edges(self, at: datetime) -> list[Relationship]:
        """Stored edges with staleness applied as of `at`. UNKNOWN and
        INVALIDATED are never overridden."""
        out: list[Relationship] = []
        for k in sorted(self._edges):
            e = self._edges[k]
            if self._is_stale(e, at):
                e = e.model_copy(update={"status": EdgeStatus.STALE})
            out.append(e)
        return out

    def _hash(self, edges: list[Relationship], time_blocked: list[str]) -> str:
        payload = {
            "entities": [
                self._entities[k].model_dump(mode="json")
                for k in sorted(self._entities)
            ],
            "edges": [e.model_dump(mode="json") for e in edges],
            "time_blocked": time_blocked,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "g_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    def _version(self, at: datetime | None = None) -> str:
        """Content + time-effective state (time-blocked and stale edges) at `at`.

        Same content and same time-effective state -> same version, so it is
        stable across wall-clock time until a window or freshness boundary is
        crossed. Raw observed_at values are NOT hashed, only their effect.
        """
        at = at or self._clock()
        return self._hash(self._effective_edges(at), self._time_blocked_ids(at))

    def _change(self, kind: ChangeKind, subject_id: str, changed: bool) -> GraphChange:
        return GraphChange(
            kind=kind, subject_id=subject_id, changed=changed, version=self._version()
        )

    # ---- writes -----------------------------------------------------
    def upsert_entity(
        self, entity: Entity, *, observed_at: datetime | None = None
    ) -> GraphChange:
        eid = entity.entity_id
        existing = self._entities.get(eid)
        if observed_at is not None and existing is not None:
            seen = self._entity_observed_at.get(eid)
            if seen is not None and observed_at <= seen:
                return self._change(ChangeKind.ENTITY_UPDATED, eid, False)
        if existing == entity:
            if observed_at is not None:
                self._entity_observed_at[eid] = observed_at
            return self._change(ChangeKind.ENTITY_UPDATED, eid, False)
        self._entities[eid] = entity
        if observed_at is not None:
            self._entity_observed_at[eid] = observed_at
        kind = ChangeKind.ENTITY_ADDED if existing is None else ChangeKind.ENTITY_UPDATED
        return self._change(kind, entity.entity_id, True)

    def upsert_edge(
        self,
        edge: Relationship,
        *,
        reinstate: bool = False,
        observed_at: datetime | None = None,
        source_api: str | None = None,
    ) -> GraphChange:
        for endpoint in (edge.source_id, edge.target_id):
            if endpoint not in self._entities:
                raise ValueError(f"unknown entity {endpoint!r} for edge {edge.edge_id}")
        eid = edge.edge_id
        existing = self._edges.get(eid)

        def ignored() -> GraphChange:
            return self._change(ChangeKind.EDGE_UPDATED, eid, False)

        if existing is not None:
            # Out-of-order / replayed delivery: need a strictly newer observation.
            if observed_at is not None:
                latest = self._latest_event_time(eid)
                if latest is not None and observed_at <= latest:
                    return ignored()
            # Replay guard: an invalidated edge stays invalidated unless this
            # is a fresh observation (newer than the invalidation).
            if (
                existing.status == EdgeStatus.INVALIDATED
                and edge.status != EdgeStatus.INVALIDATED
                and not reinstate
            ):
                inv = self._invalidated_at.get(eid)
                fresh = observed_at is not None and inv is not None and observed_at > inv
                if not fresh:
                    return ignored()

        if source_api is not None:
            self._source_api[eid] = source_api

        if existing == edge:
            # Content identical: only the freshness ledger moves.
            if observed_at is not None and edge.status != EdgeStatus.INVALIDATED:
                self._observed_at[eid] = observed_at
            return self._change(ChangeKind.EDGE_UPDATED, eid, False)

        self._edges[eid] = edge
        if edge.status == EdgeStatus.INVALIDATED:
            self._invalidated_at[eid] = observed_at or self._clock()
        else:
            if observed_at is not None:
                self._observed_at[eid] = observed_at
            if edge.status != EdgeStatus.UNKNOWN and observed_at is not None:
                self._unknown_since.pop(eid, None)  # only a newer observation clears UNKNOWN
        kind = ChangeKind.EDGE_ADDED if existing is None else ChangeKind.EDGE_UPDATED
        return self._change(kind, eid, True)

    def invalidate_edge(self, edge_id: str, *, at: datetime | None = None) -> GraphChange:
        edge = self._edges[edge_id]  # KeyError if unknown
        if edge.status == EdgeStatus.INVALIDATED:
            return self._change(ChangeKind.EDGE_INVALIDATED, edge_id, False)
        if at is not None:
            latest = self._latest_event_time(edge_id)
            if latest is not None and at <= latest:
                # Stale removal: we have seen something newer for this edge.
                return self._change(ChangeKind.EDGE_INVALIDATED, edge_id, False)
        self._edges[edge_id] = edge.model_copy(
            update={"status": EdgeStatus.INVALIDATED}
        )
        self._invalidated_at[edge_id] = at or self._clock()
        self._unknown_since.pop(edge_id, None)
        return self._change(ChangeKind.EDGE_INVALIDATED, edge_id, True)

    def mark_scope_unknown(self, scope: Scope, *, at: datetime) -> GraphChange:
        any_changed = False
        for eid in sorted(self._edges):
            edge = self._edges[eid]
            if edge.status == EdgeStatus.INVALIDATED:
                continue
            if self._source_api.get(eid) != scope.source_api:
                continue
            source = self._entities.get(edge.source_id)
            if source is None or source.account_id != scope.account_id:
                continue
            if eid not in self._observed_at:
                continue  # never observed (seed / direct write): freshness not judged
            latest = self._latest_event_time(eid)
            if latest is not None and at <= latest:
                continue  # stale failure report for this edge
            if edge.status != EdgeStatus.UNKNOWN:
                self._edges[eid] = edge.model_copy(
                    update={"status": EdgeStatus.UNKNOWN}
                )
                any_changed = True
            self._unknown_since[eid] = at
        return self._change(ChangeKind.SCOPE_MARKED_UNKNOWN, scope.key, any_changed)

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
            edges=tuple(self._effective_edges(created_at)),
        )
