"""Enumerate candidate legitimate routes by reusing P3's discover_paths."""
from __future__ import annotations

from dataclasses import dataclass

from backend.paths import discover_paths
from backend.paths.models import GraphReader
from contracts.graph import GraphSnapshot
from contracts.paths import PathOptions, make_path_id

from .config import ReroutingPolicy
from .models import AccessPath, AccessRequirement


@dataclass(frozen=True)
class AccessDiscovery:
    paths: tuple[AccessPath, ...]
    truncated: bool
    truncation_reason: str | None
    unknown_endpoints: tuple[str, ...]
    graph_version: str

    @property
    def complete(self) -> bool:
        """False means 'absence of a route is NOT proven'."""
        return not self.truncated and not self.unknown_endpoints


def discover_access_paths(
    graph: GraphReader, req: AccessRequirement, policy: ReroutingPolicy | None = None
) -> AccessDiscovery:
    policy = policy or ReroutingPolicy()
    options = PathOptions(max_depth=req.max_hops, max_paths=policy.max_candidates)
    res = discover_paths(graph, [req.principal_id], [req.resource_id], options)
    return AccessDiscovery(
        paths=tuple(AccessPath.from_p3(p) for p in res.paths),
        truncated=res.stats.truncated,
        truncation_reason=res.stats.truncation_reason,
        unknown_endpoints=tuple(res.stats.unknown_entry_ids + res.stats.unknown_target_ids),
        graph_version=res.graph_version,
    )


def build_explicit_path(
    snapshot: GraphSnapshot, req: AccessRequirement, edge_ids: tuple[str, ...]
) -> tuple[AccessPath | None, str | None]:
    """Caller-supplied edge ids -> AccessPath, or (None, reason). Never guesses."""
    nodes = [req.principal_id]
    for eid in edge_ids:
        edge = snapshot.get_edge(eid)
        if edge is None:
            return None, f"edge {eid} not in snapshot {snapshot.version}"
        if edge.source_id != nodes[-1]:
            return None, f"edge {eid} does not continue from {nodes[-1]}"
        nodes.append(edge.target_id)
    if nodes[-1] != req.resource_id:
        return None, f"route ends at {nodes[-1]}, not {req.resource_id}"
    if len(set(nodes)) != len(nodes) or len(set(edge_ids)) != len(edge_ids):
        return None, "route revisits a node or edge"
    return AccessPath(
        path_id=make_path_id(edge_ids), graph_version=snapshot.version,
        principal_id=req.principal_id, resource_id=req.resource_id,
        node_ids=tuple(nodes), edge_ids=edge_ids,
    ), None
