"""Freshness, out-of-order delivery and scope-unknown rules (P2 repository)."""
from datetime import datetime, timedelta, timezone

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.models import ChangeKind, Scope
from contracts import (
    EdgeStatus,
    Entity,
    NodeType,
    RelationType,
    Relationship,
)

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
ACCT = "111122223333"
API = "iam:GetAccountAuthorizationDetails"
SCOPE = Scope(ACCT, API)


def h(n: int) -> timedelta:
    return timedelta(hours=n)


def _repo(window=h(24)):
    now = [T0]
    repo = InMemoryGraphRepository(clock=lambda: now[0], freshness_window=window)
    for name, typ in (("alice", NodeType.IAM_USER), ("dev", NodeType.IAM_GROUP)):
        repo.upsert_entity(
            Entity(entity_id=name, entity_type=typ, name=name, account_id=ACCT)
        )
    return repo, now


def _edge(status=EdgeStatus.CONFIRMED, **kw):
    return Relationship(
        source_id="alice",
        target_id="dev",
        relation_type=RelationType.MEMBER_OF,
        status=status,
        **kw,
    )


def _seen(repo, edge, at, api=API):
    return repo.upsert_edge(edge, observed_at=at, source_api=api)


# ---- freshness --------------------------------------------------------
def test_edge_becomes_stale_in_snapshot_not_in_store():
    repo, now = _repo()
    e = _edge()
    _seen(repo, e, T0)
    assert repo.snapshot().edges[0].status == EdgeStatus.CONFIRMED
    now[0] = T0 + h(24)  # boundary is inclusive, like valid_until
    snap = repo.snapshot()
    assert snap.edges[0].status == EdgeStatus.STALE
    assert repo.get_edge(e.edge_id).status == EdgeStatus.CONFIRMED


def test_version_changes_when_edge_goes_stale_and_not_before():
    repo, now = _repo()
    _seen(repo, _edge(), T0)
    v1 = repo.snapshot().version
    now[0] = T0 + h(23)
    assert repo.snapshot().version == v1
    now[0] = T0 + h(25)
    assert repo.snapshot().version != v1


def test_refresh_makes_edge_fresh_again():
    repo, now = _repo()
    e = _edge()
    _seen(repo, e, T0)
    now[0] = T0 + h(30)
    assert repo.snapshot().edges[0].status == EdgeStatus.STALE
    change = _seen(repo, e, T0 + h(29))  # re-observation, same content
    assert change.changed is False
    assert repo.snapshot().edges[0].status == EdgeStatus.CONFIRMED


def test_edge_without_observed_at_is_not_judged_and_window_none_disables():
    repo, now = _repo()
    repo.upsert_edge(_edge())  # direct write, no observation time
    now[0] = T0 + h(1000)
    assert repo.snapshot().edges[0].status == EdgeStatus.CONFIRMED
    repo2, now2 = _repo(window=None)
    _seen(repo2, _edge(), T0)
    now2[0] = T0 + h(1000)
    assert repo2.snapshot().edges[0].status == EdgeStatus.CONFIRMED


# ---- ordering ---------------------------------------------------------
def test_older_observation_does_not_overwrite_newer():
    repo, _ = _repo()
    new = _edge(conditions={"mfa": True})
    old = _edge(conditions={})
    _seen(repo, new, T0 + h(2))
    change = _seen(repo, old, T0 + h(1))
    assert change.changed is False
    assert repo.get_edge(new.edge_id).conditions == {"mfa": True}


def test_older_removal_is_ignored_newer_removal_applies():
    repo, _ = _repo()
    e = _edge()
    _seen(repo, e, T0 + h(2))
    assert repo.invalidate_edge(e.edge_id, at=T0 + h(1)).changed is False
    assert repo.get_edge(e.edge_id).status == EdgeStatus.CONFIRMED
    assert repo.invalidate_edge(e.edge_id, at=T0 + h(3)).changed is True
    assert repo.get_edge(e.edge_id).status == EdgeStatus.INVALIDATED


def test_old_replay_after_removal_ignored_fresh_regrant_reinstates():
    repo, _ = _repo()
    e = _edge()
    _seen(repo, e, T0 + h(1))
    repo.invalidate_edge(e.edge_id, at=T0 + h(3))
    assert _seen(repo, e, T0 + h(2)).changed is False  # old replay
    assert repo.get_edge(e.edge_id).status == EdgeStatus.INVALIDATED
    assert _seen(repo, e, T0 + h(4)).changed is True  # fresh re-grant
    assert repo.get_edge(e.edge_id).status == EdgeStatus.CONFIRMED


# ---- scope unknown ----------------------------------------------------
def test_failed_scope_marks_edge_unknown_and_snapshot_shows_it():
    repo, _ = _repo()
    e = _edge()
    _seen(repo, e, T0)
    change = repo.mark_scope_unknown(SCOPE, at=T0 + h(1))
    assert change.kind == ChangeKind.SCOPE_MARKED_UNKNOWN
    assert change.subject_id == SCOPE.key and change.changed is True
    assert repo.snapshot().edges[0].status == EdgeStatus.UNKNOWN


def test_unknown_survives_old_observation_cleared_by_newer():
    repo, _ = _repo()
    e = _edge()
    _seen(repo, e, T0)
    repo.mark_scope_unknown(SCOPE, at=T0 + h(2))
    assert _seen(repo, e, T0 + h(1)).changed is False  # older run arrives late
    assert repo.get_edge(e.edge_id).status == EdgeStatus.UNKNOWN
    assert _seen(repo, e, T0 + h(3)).changed is True  # later completed run
    assert repo.get_edge(e.edge_id).status == EdgeStatus.CONFIRMED


def test_scope_isolation_and_invalidated_untouched():
    repo, _ = _repo()
    other = _edge()
    _seen(repo, other, T0, api="s3:ListBuckets")
    assert repo.mark_scope_unknown(SCOPE, at=T0 + h(1)).changed is False
    assert repo.get_edge(other.edge_id).status == EdgeStatus.CONFIRMED

    repo2, _ = _repo()
    gone = _edge()
    _seen(repo2, gone, T0)
    repo2.invalidate_edge(gone.edge_id, at=T0 + h(1))
    assert repo2.mark_scope_unknown(SCOPE, at=T0 + h(2)).changed is False
    assert repo2.get_edge(gone.edge_id).status == EdgeStatus.INVALIDATED


def test_late_failure_report_does_not_hide_newer_observation():
    repo, _ = _repo()
    e = _edge()
    _seen(repo, e, T0 + h(5))
    assert repo.mark_scope_unknown(SCOPE, at=T0 + h(2)).changed is False
    assert repo.get_edge(e.edge_id).status == EdgeStatus.CONFIRMED