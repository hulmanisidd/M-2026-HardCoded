"""Incremental recompute, out-of-order handling and stale-result protection."""
from datetime import datetime, timedelta, timezone

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.models import ChangeKind, GraphChange
from backend.updates import UpdateCoordinator, UpdateStrategy
from contracts import PathOptions
from p5_helpers import (
    chain_repo, counting, edge, entity, index_matches_fresh, seed_setup,
)


def test_incremental_result_equals_full_recompute_for_every_seed_edge():
    """Invalidate each edge of the seed in turn; state must equal a fresh P3 run."""
    _, _, entries, targets = seed_setup()
    probe_repo, _, _, _ = seed_setup()
    edge_ids = [e.edge_id for e in probe_repo.snapshot().edges]
    assert edge_ids
    for edge_id in edge_ids:
        repo, _, entries, targets = seed_setup()
        coord = counting(repo.snapshot, entries, targets)
        coord.initialize()
        coord.handle_change(repo.invalidate_edge(edge_id))
        assert index_matches_fresh(coord, repo, entries, targets), edge_id


def test_invalidating_a_used_edge_is_incremental_not_full():
    repo, _, entries, targets = seed_setup()
    coord = counting(repo.snapshot, entries, targets)
    coord.initialize()
    used = sorted({e for p in coord.dependency_index.all_paths() for e in p.edge_ids})[0]
    runs = type(coord).searches

    result = coord.handle_change(repo.invalidate_edge(used))

    assert result.strategy == UpdateStrategy.INCREMENTAL
    assert type(coord).searches == runs            # no new P3 discovery
    assert result.dropped_path_ids
    assert index_matches_fresh(coord, repo, entries, targets)


def test_unrelated_changes_do_not_trigger_recomputation():
    repo, _, entries, targets = seed_setup()
    coord = counting(repo.snapshot, entries, targets)
    coord.initialize()
    runs = type(coord).searches
    before = {p.path_id for p in coord.dependency_index.all_paths()}

    # A brand-new isolated entity, and an edge into a dead end off a reachable node.
    r1 = coord.handle_change(repo.upsert_entity(entity("isolated")))
    dev_scratch = "arn:aws:s3:::dev-scratch"
    r2 = coord.handle_change(repo.upsert_entity(entity("dead-end")))
    r3 = coord.handle_change(repo.upsert_edge(edge(dev_scratch, "dead-end")))

    assert [r.strategy for r in (r1, r2, r3)] == [UpdateStrategy.SKIPPED] * 3
    assert all(r.applied and r.reason == "no_path_impact" for r in (r1, r2, r3))
    assert type(coord).searches == runs
    assert {p.path_id for p in coord.dependency_index.all_paths()} == before
    # Skipped changes still leave every path tagged with the newest version.
    assert index_matches_fresh(coord, repo, entries, targets)


def test_edge_that_opens_a_new_route_triggers_full_recompute():
    repo, edges = chain_repo("a", "b", "c")
    repo.upsert_entity(entity("shortcut-src"))
    coord = counting(repo.snapshot, ["a"], ["c"])
    coord.initialize()
    runs = type(coord).searches

    result = coord.handle_change(repo.upsert_edge(edge("a", "c")))

    assert result.strategy == UpdateStrategy.FULL
    assert type(coord).searches == runs + 1
    assert len(coord.dependency_index) == 2
    assert index_matches_fresh(coord, repo, ["a"], ["c"])


def test_truncated_earlier_search_forces_full_recompute():
    repo, _, entries, targets = seed_setup()
    coord = counting(repo.snapshot, entries, targets, options=PathOptions(max_paths=1))
    coord.initialize()
    used = sorted({e for p in coord.dependency_index.all_paths() for e in p.edge_ids})[0]
    result = coord.handle_change(repo.invalidate_edge(used))
    assert result.strategy == UpdateStrategy.FULL


def test_out_of_order_notifications_never_lose_a_change():
    repo, _, entries, targets = seed_setup()
    coord = counting(repo.snapshot, entries, targets)
    coord.initialize()
    ids = sorted({e for p in coord.dependency_index.all_paths() for e in p.edge_ids})
    c1 = repo.invalidate_edge(ids[0])
    c2 = repo.invalidate_edge(ids[-1])

    late = coord.handle_change(c1)           # arrives after c2's write: graph moved on
    assert late.applied is False and late.reason == "graph_version_mismatch"
    assert coord.needs_resync is True
    on_time = coord.handle_change(c2)        # must catch up on c1 as well
    assert on_time.applied is True and on_time.strategy == UpdateStrategy.FULL
    assert coord.needs_resync is False
    assert index_matches_fresh(coord, repo, entries, targets)


def test_duplicate_and_replayed_notifications_are_noops():
    repo, edges = chain_repo("a", "b", "c")
    coord = counting(repo.snapshot, ["a"], ["c"])
    coord.initialize()
    change = repo.invalidate_edge(edges[0].edge_id)
    assert coord.handle_change(change).applied is True
    again = coord.handle_change(change)                       # same notification twice
    assert again.applied is False and again.reason == "already_processed_version"
    replay = coord.handle_change(repo.invalidate_edge(edges[0].edge_id))
    assert replay.reason == "replayed_change"


def test_older_result_cannot_overwrite_a_newer_one():
    """Outer computation starts first but finishes last; its result is discarded."""
    repo, edges = chain_repo("a", "b", "c", "d")
    box = {"armed": False, "nested": None}

    class Racing(UpdateCoordinator):
        def search(self, graph):
            result = super().search(graph)           # outer has computed on OLD state...
            if box["armed"]:
                box["armed"] = False
                # ...while a newer write lands and is fully processed.
                box["nested"] = self.handle_change(repo.invalidate_edge(edges[2].edge_id))
            return result

    coord = Racing(repo.snapshot, ["a"], ["d"])
    coord.initialize()
    assert len(coord.dependency_index) == 1

    box["armed"] = True
    outer = coord.handle_change(repo.upsert_edge(edge("a", "d")))   # on-route -> full

    nested = box["nested"]
    assert nested is not None and nested.applied is True
    assert nested.strategy == UpdateStrategy.FULL    # saw a computation in flight
    assert outer.applied is False and outer.reason == "stale_result"
    # The newer state (c->d invalidated, a->d present) was not overwritten by
    # the older outer result, and the index equals a from-scratch run.
    assert index_matches_fresh(coord, repo, ["a"], ["d"])
    assert len(coord.dependency_index) == 1
    assert coord.needs_resync is True                # next change re-verifies fully


def test_time_based_expiry_is_not_hidden_by_a_skipped_change():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    now = {"t": t0}
    repo = InMemoryGraphRepository(clock=lambda: now["t"])
    for n in ("a", "b", "c"):
        repo.upsert_entity(entity(n))
    repo.upsert_edge(edge("a", "b"))
    repo.upsert_edge(edge("b", "c", valid_until=t0 + timedelta(hours=1)))
    coord = counting(repo.snapshot, ["a"], ["c"])
    coord.initialize()
    assert len(coord.dependency_index) == 1

    now["t"] = t0 + timedelta(hours=2)                       # b->c expires, no write
    result = coord.handle_change(repo.upsert_entity(entity("isolated")))

    assert result.strategy == UpdateStrategy.FULL            # not skipped
    assert len(coord.dependency_index) == 0
    assert index_matches_fresh(coord, repo, ["a"], ["c"])
