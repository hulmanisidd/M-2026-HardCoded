"""Reconciliation detects missed updates and drift, repairs only via P2."""
from datetime import timedelta

from backend.updates import (
    DriftKind, OverallState, Reconciler, ReconciliationStatus, SourceEvidence,
    SourceInventory, StatusTracker, UpdateCoordinator,
)
from contracts.relationships import EdgeStatus
from p5_helpers import chain_repo, edge, entity, index_matches_fresh, seed_setup, source_from


def setup(provider, *, repo=None, entries=("a",), targets=("c",)):
    if repo is None:
        repo, _ = chain_repo("a", "b", "c")
    status = StatusTracker()
    coord = UpdateCoordinator(repo.snapshot, entries, targets, status=status)
    coord.initialize()
    return repo, coord, status, Reconciler(repo, coord, provider, status=status)


def inv(repo, **kw):
    complete = kw.pop("complete", True)
    return SourceInventory(snapshot=source_from(repo, **kw), collected_at=_now(), complete=complete)


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def test_in_sync_when_source_equals_graph():
    repo, _ = chain_repo("a", "b", "c")
    _, coord, status, rec = setup(lambda: inv(repo), repo=repo)
    res = rec.reconcile()
    assert res.status == ReconciliationStatus.IN_SYNC
    assert res.drift == () and res.missed_update_detected is False
    assert res.evidence == SourceEvidence.SOURCE_CONFIRMED
    assert status.summary().overall == OverallState.OK


def test_missed_graph_update_is_detected_and_paths_refreshed():
    repo, edges = chain_repo("a", "b", "c")
    _, coord, _, rec = setup(lambda: inv(repo), repo=repo)
    assert len(coord.dependency_index) == 1

    repo.invalidate_edge(edges[1].edge_id)       # P2 write that P5 never heard about

    res = rec.reconcile()
    assert res.missed_update_detected is True
    assert any(d.kind == DriftKind.VERSION_DRIFT and d.repaired for d in res.drift)
    assert res.status == ReconciliationStatus.DRIFT_REPAIRED
    assert len(coord.dependency_index) == 0
    assert index_matches_fresh(coord, repo, ["a"], ["c"])
    # And a second pass finds nothing left to fix.
    assert rec.reconcile().status == ReconciliationStatus.IN_SYNC


def test_edge_gone_from_source_is_invalidated_never_deleted():
    repo, edges = chain_repo("a", "b", "c")
    gone = edges[1].edge_id
    _, coord, _, rec = setup(lambda: inv(repo, drop_edges=[gone]), repo=repo)
    res = rec.reconcile()
    assert res.status == ReconciliationStatus.DRIFT_REPAIRED
    assert [d.kind for d in res.drift] == [DriftKind.EDGE_NOT_IN_SOURCE]
    assert repo.get_edge(gone).status == EdgeStatus.INVALIDATED      # kept for history
    assert len(coord.dependency_index) == 0


def test_new_source_edge_and_entity_are_added_and_open_a_path():
    repo, edges = chain_repo("a", "b", "c")
    repo.invalidate_edge(edges[1].edge_id)
    _, coord, _, rec = setup(lambda: None, repo=repo)    # provider replaced below
    new_e = entity("z")
    shortcut = edge("a", "c")
    rec = Reconciler(repo, coord, lambda: inv(repo, add_edges=[shortcut], extra_entities=[new_e]),
                     status=StatusTracker())
    res = rec.reconcile()
    kinds = {d.kind for d in res.drift}
    assert DriftKind.ENTITY_MISSING_IN_GRAPH in kinds and DriftKind.EDGE_MISSING_IN_GRAPH in kinds
    assert all(d.repaired for d in res.drift if d.kind != DriftKind.VERSION_DRIFT)
    assert repo.get_edge(shortcut.edge_id) is not None
    assert len(coord.dependency_index) == 1
    assert index_matches_fresh(coord, repo, ["a"], ["c"])


def test_edge_reinstated_when_source_still_shows_it_confirmed():
    repo, edges = chain_repo("a", "b", "c")
    src = source_from(repo)                                   # source: edge b->c confirmed
    repo.invalidate_edge(edges[1].edge_id)                    # graph wrongly says gone
    from datetime import datetime, timezone
    _, coord, _, _ = setup(lambda: None, repo=repo)
    rec = Reconciler(repo, coord, lambda: SourceInventory(src, datetime.now(timezone.utc)),
                     status=StatusTracker())
    res = rec.reconcile()
    assert any(d.kind == DriftKind.EDGE_CHANGED and d.repaired for d in res.drift)
    assert repo.get_edge(edges[1].edge_id).status == EdgeStatus.CONFIRMED


def test_unreadable_source_is_unknown_and_recorded_as_failed():
    repo, _ = chain_repo("a", "b", "c")

    def boom():
        raise TimeoutError("sts timed out")

    _, coord, status, rec = setup(boom, repo=repo)
    res = rec.reconcile()
    assert res.status == ReconciliationStatus.UNKNOWN
    assert res.evidence == SourceEvidence.SOURCE_UNAVAILABLE
    assert any("TimeoutError" in r for r in res.reasons)
    s = status.summary()
    assert s.overall != OverallState.OK
    assert s.sources[0].state.value == "failed"


def test_partial_inventory_never_claims_in_sync_and_never_invalidates():
    repo, edges = chain_repo("a", "b", "c")
    gone = edges[1].edge_id
    _, coord, status, rec = setup(lambda: inv(repo, drop_edges=[gone], complete=False), repo=repo)
    res = rec.reconcile()
    assert res.status == ReconciliationStatus.UNKNOWN
    assert res.evidence == SourceEvidence.SOURCE_STALE
    assert repo.get_edge(gone).status == EdgeStatus.CONFIRMED         # absence is not proof
    assert any(d.kind == DriftKind.EDGE_NOT_IN_SOURCE and not d.repaired for d in res.drift)
    assert len(coord.dependency_index) == 1
    assert status.summary().unresolved_drift == 1


def test_old_inventory_is_downgraded_to_stale_evidence():
    from datetime import datetime, timezone
    repo, _ = chain_repo("a", "b", "c")
    old = SourceInventory(source_from(repo), datetime.now(timezone.utc) - timedelta(days=3))
    _, _, _, rec = setup(lambda: old, repo=repo)
    res = rec.reconcile()
    assert res.status == ReconciliationStatus.IN_SYNC
    assert res.evidence == SourceEvidence.SOURCE_STALE


def test_extra_entity_in_graph_is_reported_not_removed():
    repo, _ = chain_repo("a", "b", "c")
    repo.upsert_entity(entity("ghost"))
    _, coord, _, rec = setup(lambda: inv(repo, drop_entities=["ghost"]), repo=repo)
    res = rec.reconcile()
    assert res.status == ReconciliationStatus.DRIFT_DETECTED
    assert repo.get_entity("ghost") is not None
    assert [d.kind for d in res.drift if not d.repaired] == [DriftKind.ENTITY_NOT_IN_SOURCE]


def test_reconcile_on_seed_organisation_is_in_sync():
    repo, _, entries, targets = seed_setup()
    _, coord, _, rec = setup(lambda: inv(repo), repo=repo, entries=entries, targets=targets)
    assert rec.reconcile().status == ReconciliationStatus.IN_SYNC
