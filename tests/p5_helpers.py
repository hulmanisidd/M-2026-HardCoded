"""Shared builders for the P5 tests."""
from datetime import datetime, timezone
from functools import partial

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.seed_data import ENTRY_KEYS, TARGET_KEYS, load_into
from backend.paths import discover_paths
from backend.updates import UpdateCoordinator
from contracts import (
    Criticality, EdgeStatus, Entity, GraphSnapshot, NodeType, PathOptions,
    RelationType, Relationship,
)
from contracts.paths import FeasibilityStatus


def entity(entity_id: str, crit=Criticality.LOW) -> Entity:
    return Entity(entity_id=entity_id, entity_type=list(NodeType)[0], name=entity_id, criticality=crit)


def edge(source: str, target: str, status=EdgeStatus.CONFIRMED, **kw) -> Relationship:
    return Relationship(source_id=source, target_id=target,
                        relation_type=RelationType.CAN_ASSUME, status=status, **kw)


def chain_repo(*node_ids, clock=None):
    """Repo with a straight chain n0 -> n1 -> ... (all CONFIRMED)."""
    repo = InMemoryGraphRepository(clock=clock) if clock else InMemoryGraphRepository()
    for n in node_ids:
        repo.upsert_entity(entity(n))
    edges = [edge(a, b) for a, b in zip(node_ids, node_ids[1:])]
    for e in edges:
        repo.upsert_edge(e)
    return repo, edges


def seed_setup():
    repo = InMemoryGraphRepository()
    seed = load_into(repo)
    entries = [seed.entity_ids[k] for k in ENTRY_KEYS]
    targets = [seed.entity_ids[k] for k in TARGET_KEYS]
    return repo, seed, entries, targets


def live(paths):
    return {p.path_id for p in paths if p.feasibility_status != FeasibilityStatus.BLOCKED}


def fresh_paths(repo, entries, targets, options=None):
    return discover_paths(repo.snapshot(), entries, targets, options or PathOptions()).paths


def index_matches_fresh(coordinator, repo, entries, targets, options=None) -> bool:
    """Coordinator state == a from-scratch P3 run, including the version tag."""
    snap = repo.snapshot()
    fresh = {p.path_id: p for p in
             discover_paths(snap, entries, targets, options or PathOptions()).paths}
    mine = {p.path_id: p for p in coordinator.dependency_index.all_paths()}
    return fresh == mine


class CountingCoordinator(UpdateCoordinator):
    """Counts how many full P3 discoveries ran."""
    searches = 0

    def search(self, graph):
        type(self).searches += 1
        return super().search(graph)


def counting(factory, entries, targets, **kw):
    class _C(CountingCoordinator):
        searches = 0
    return _C(factory, entries, targets, **kw)


def source_from(repo, *, drop_edges=(), add_edges=(), extra_entities=(), drop_entities=()):
    """An 'authoritative inventory' snapshot derived from the repo's graph."""
    snap = repo.snapshot()
    edges = tuple(e for e in snap.edges if e.edge_id not in set(drop_edges)) + tuple(add_edges)
    entities = tuple(e for e in snap.entities if e.entity_id not in set(drop_entities)) + tuple(extra_entities)
    return GraphSnapshot(version="source", created_at=snap.created_at, entities=entities, edges=edges)
