"""Notebook of "which edge is used by which paths".

When an edge changes we look it up here and redo only the affected paths,
instead of recomputing everything.
"""
from __future__ import annotations

from collections.abc import Iterable

from contracts.paths import AttackPath


class DependencyIndex:
    def __init__(self) -> None:
        self._paths: dict[str, AttackPath] = {}
        self._by_edge: dict[str, set[str]] = {}

    def register(self, paths: Iterable[AttackPath]) -> None:
        """Add or replace paths. Re-registering the same path_id is safe."""
        for path in paths:
            if path.path_id in self._paths:
                self.remove([path.path_id])
            self._paths[path.path_id] = path
            for edge_id in path.edge_ids:
                self._by_edge.setdefault(edge_id, set()).add(path.path_id)

    def remove(self, path_ids: Iterable[str]) -> None:
        for path_id in path_ids:
            path = self._paths.pop(path_id, None)
            if path is None:
                continue
            for edge_id in path.edge_ids:
                users = self._by_edge.get(edge_id)
                if users is not None:
                    users.discard(path_id)
                    if not users:
                        del self._by_edge[edge_id]

    def paths_using(self, edge_id: str) -> frozenset[str]:
        return frozenset(self._by_edge.get(edge_id, ()))

    def affected_paths(self, edge_ids: Iterable[str]) -> tuple[str, ...]:
        """Sorted path idsthat use ANY of the given edges."""
        hit: set[str] = set()
        for edge_id in edge_ids:
            hit |= self._by_edge.get(edge_id, set())
        return tuple(sorted(hit))

    def get(self, path_id: str) -> AttackPath | None:
        return self._paths.get(path_id)

    def all_paths(self) -> tuple[AttackPath, ...]:
        return tuple(self._paths[k] for k in sorted(self._paths))

    def __len__(self) -> int:
        return len(self._paths)