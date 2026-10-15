"""Coordinate graph changes with attack-path discovery (P2, P3 and P5).

Recompute strategy for one real graph change (cheapest correct option):

* SKIPPED     - the change provably cannot affect any route (an edge nowhere
                near an entry-to-target route, a new isolated entity...).
* INCREMENTAL - an edge that known paths use was invalidated. Removing an edge
                can only remove paths, so exactly those paths are dropped.
* FULL        - anything that could add or alter routes, or whenever the
                incremental shortcut is unsafe (earlier search was truncated,
                blocked paths are requested, updates were missed or ran
                concurrently, the reader cannot describe the edge).

The result is always identical to a from-scratch P3 run on the new graph; the
tests check that equivalence for every edge of the seed organization.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable, Iterable

from backend.graph.models import ChangeKind, GraphChange
from backend.paths import discover_paths
from backend.paths.models import GraphReader, PathSearchResult
from contracts.paths import PathOptions
from contracts.relationships import EdgeStatus

from .dependencies import DependencyIndex
from .models import UpdateResult, UpdateStrategy
from .status import StatusTracker
from .versioning import EpochGuard

UpdateHook = Callable[[UpdateResult, GraphReader], None]


class UpdateCoordinator:
    """Recompute and maintain attack paths after graph changes.

    `graph_reader_factory` must return a P3-compatible reader for the
    current graph state. Entry points and targets are supplied by the caller.
    """

    def __init__(
        self,
        graph_reader_factory: Callable[[], GraphReader],
        entry_points: Iterable[str],
        targets: Iterable[str],
        *,
        dependency_index: DependencyIndex | None = None,
        options: PathOptions | None = None,
        status: StatusTracker | None = None,
        on_update: UpdateHook | None = None,
    ) -> None:
        self._graph_reader_factory = graph_reader_factory
        self._entry_points = tuple(dict.fromkeys(entry_points))
        self._targets = tuple(dict.fromkeys(targets))
        self._index = dependency_index or DependencyIndex()
        self._options = options or PathOptions()
        self._status = status
        self._on_update = on_update
        self._last_version: str | None = None
        self._last_stats: PathSearchResult | None = None
        self._needs_resync = False
        self._last_time_blocked: frozenset[str] | None = None
        self._guard = EpochGuard()
        self._lock = threading.RLock()

    # ---- inspection --------------------------------------------------
    @property
    def dependency_index(self) -> DependencyIndex:
        """Expose the path-to-edge notebook for inspection."""
        return self._index

    @property
    def last_version(self) -> str | None:
        return self._last_version

    @property
    def needs_resync(self) -> bool:
        return self._needs_resync

    @property
    def entry_points(self) -> tuple[str, ...]:
        return self._entry_points

    @property
    def targets(self) -> tuple[str, ...]:
        return self._targets

    @property
    def options(self) -> PathOptions:
        return self._options

    def search(self, graph: GraphReader) -> PathSearchResult:
        """Run P3 discovery with this coordinator's scope (entries/targets/options)."""
        return discover_paths(graph, self._entry_points, self._targets, self._options)

    # ---- public operations ------------------------------------------
    def initialize(self) -> UpdateResult:
        """Perform initial discovery and populate the dependency index."""
        graph = self._graph_reader_factory()
        epoch, _ = self._guard.begin()
        result = self._run_full(
            graph, epoch, reason="initial_discovery", report_all=True
        )
        return self._finish(result, graph)

    def resync(self, reason: str = "resync") -> UpdateResult:
        """Force a full rediscovery against the current graph.

        Used by reconciliation after a missed update was detected.
        """
        graph = self._graph_reader_factory()
        epoch, _ = self._guard.begin()
        result = self._run_full(graph, epoch, reason=reason)
        return self._finish(result, graph)

    def handle_change(self, change: GraphChange) -> UpdateResult:
        """Handle one P2 graph-write event.

        Replayed writes are no-ops. Duplicate, late and out-of-order
        notifications never corrupt state: a notification whose version is not
        the current one is rejected and the coordinator remembers it must do a
        full recompute before trusting an incremental one again.
        """
        if not change.changed:
            return UpdateResult(
                applied=False,
                reason="replayed_change",
                graph_version=change.version,
            )

        graph = self._graph_reader_factory()

        if graph.version != change.version:
            # Late, early or out-of-order notification. The graph state is
            # ahead of (or unrelated to) it, so the next accepted change (or a
            # reconcile) must rediscover everything.
            self._needs_resync = True
            return self._finish(
                UpdateResult(
                    applied=False,
                    reason="graph_version_mismatch",
                    graph_version=graph.version,
                ),
                graph,
            )

        if self._last_version is not None and graph.version == self._last_version:
            return UpdateResult(
                applied=False,
                reason="already_processed_version",
                graph_version=graph.version,
            )

        epoch, concurrent = self._guard.begin()
        try:
            action, affected = self._classify(graph, change, force_full=concurrent)
            if action == "skip":
                result = self._run_skip(graph, epoch)
            elif action == "invalidate":
                result = self._run_invalidate(graph, epoch, affected)
            else:
                result = self._run_full(
                    graph, epoch, reason="graph_change_processed", affected=affected
                )
        except BaseException:
            self._guard.abort(epoch)
            raise
        return self._finish(result, graph)

    # ---- classification ---------------------------------------------
    def _classify(
        self, graph: GraphReader, change: GraphChange, *, force_full: bool
    ) -> tuple[str, tuple[str, ...]]:
        """Return ("skip"|"invalidate"|"full", affected_path_ids)."""
        kind = change.kind
        affected: tuple[str, ...] = ()
        if kind in {
            ChangeKind.EDGE_ADDED,
            ChangeKind.EDGE_UPDATED,
            ChangeKind.EDGE_INVALIDATED,
        }:
            affected = self._index.affected_paths([change.subject_id])

        if (
            force_full
            or self._last_version is None
            or self._time_blocked(graph) != self._last_time_blocked
            or self._needs_resync
            or self._options.include_blocked
            or (self._last_stats is not None and self._last_stats.stats.truncated)
        ):
            return "full", affected

        if kind in {ChangeKind.ENTITY_ADDED, ChangeKind.ENTITY_UPDATED}:
            eid = change.subject_id
            if (
                eid in self._entry_points
                or eid in self._targets
                or self._index.paths_visiting(eid)
            ):
                return "full", affected
            return "skip", ()

        get_edge = getattr(graph, "get_edge", None)
        edge = get_edge(change.subject_id) if callable(get_edge) else None
        if edge is None:
            return "full", affected  # cannot describe the edge: be safe

        if kind == ChangeKind.EDGE_INVALIDATED or edge.status == EdgeStatus.INVALIDATED:
            return ("invalidate", affected) if affected else ("skip", ())

        # Edge added or updated and still live: it could create a route or
        # change the feasibility of routes that already use it.
        if affected or self._on_route(graph, edge.source_id, edge.target_id):
            return "full", affected
        return "skip", ()

    @staticmethod
    def _time_blocked(graph: GraphReader) -> frozenset[str] | None:
        """Edges whose validity window excludes the snapshot time.

        Time passing can block or unblock edges without any write. If that set
        moved since the last computation (or cannot be determined, because the
        reader does not expose its edges) incremental shortcuts are unsafe.
        """
        edges = getattr(graph, "edges", None)
        now = getattr(graph, "created_at", None)
        if edges is None or now is None:
            return None
        return frozenset(
            e.edge_id
            for e in edges
            if (e.valid_from and now < e.valid_from)
            or (e.valid_until and now >= e.valid_until)
        )

    def _forward(self, graph: GraphReader, starts: Iterable[str]) -> set[str]:
        """Nodes reachable from `starts`, ignoring everything except invalidation."""
        seen = set(starts)
        queue = deque(seen)
        while queue:
            node = queue.popleft()
            for e in graph.get_neighbors(node):
                if e.status == EdgeStatus.INVALIDATED or e.target_id in seen:
                    continue
                seen.add(e.target_id)
                queue.append(e.target_id)
        return seen

    def _on_route(self, graph: GraphReader, source: str, target: str) -> bool:
        """Conservative: could an entry->target route pass through this edge?"""
        if source not in self._forward(graph, self._entry_points):
            return False
        goals = set(self._targets)
        return target in goals or bool(self._forward(graph, [target]) & goals)

    # ---- execution ---------------------------------------------------
    def _run_skip(self, graph: GraphReader, epoch: int) -> UpdateResult:
        with self._lock:
            if not self._guard.commit(epoch):
                return self._stale(graph)
            self._index.retag(graph.version)
            self._last_version = graph.version
            self._last_time_blocked = self._time_blocked(graph)
        return UpdateResult(
            applied=True,
            reason="no_path_impact",
            graph_version=graph.version,
            strategy=UpdateStrategy.SKIPPED,
        )

    def _run_invalidate(
        self, graph: GraphReader, epoch: int, affected: tuple[str, ...]
    ) -> UpdateResult:
        with self._lock:
            if not self._guard.commit(epoch):
                return self._stale(graph)
            self._index.remove(affected)
            self._index.retag(graph.version)
            self._last_version = graph.version
            self._last_time_blocked = self._time_blocked(graph)
        return UpdateResult(
            applied=True,
            reason="graph_change_processed",
            graph_version=graph.version,
            dropped_path_ids=tuple(sorted(affected)),
            strategy=UpdateStrategy.INCREMENTAL,
        )

    def _run_full(
        self,
        graph: GraphReader,
        epoch: int,
        *,
        reason: str,
        affected: tuple[str, ...] = (),
        report_all: bool = False,
    ) -> UpdateResult:
        try:
            discovery = self.search(graph)
        except BaseException:
            self._guard.abort(epoch)
            raise

        with self._lock:
            if not self._guard.commit(epoch):
                return self._stale(graph)

            old = {p.path_id for p in self._index.all_paths()}
            new_paths = {p.path_id: p for p in discovery.paths}
            dropped = tuple(sorted(old - new_paths.keys()))

            # Vanished paths are removed; all discovered paths are registered
            # so graph versions and edge dependencies stay current.
            self._index.remove(dropped)
            self._index.register(new_paths.values())
            self._last_version = discovery.graph_version
            self._last_stats = discovery
            self._last_time_blocked = self._time_blocked(graph)
            self._needs_resync = False

        if report_all:
            recomputed = set(new_paths)
        else:
            recomputed = set(affected)
            recomputed.update(new_paths.keys() - old)
            recomputed.intersection_update(new_paths.keys())

        return UpdateResult(
            applied=True,
            reason=reason,
            graph_version=discovery.graph_version,
            recomputed_path_ids=tuple(sorted(recomputed)),
            dropped_path_ids=dropped,
            strategy=UpdateStrategy.FULL,
        )

    def _stale(self, graph: GraphReader) -> UpdateResult:
        """A newer computation already committed; discard this older one."""
        self._needs_resync = True
        return UpdateResult(
            applied=False,
            reason="stale_result",
            graph_version=graph.version,
        )

    def _finish(self, result: UpdateResult, graph: GraphReader) -> UpdateResult:
        if self._status is not None:
            self._status.record_update(result, path_count=len(self._index))
        if self._on_update is not None and result.applied:
            self._on_update(result, graph)
        return result
