"""Repository-level freshness, ordering and scope-unknown behaviour."""
from datetime import datetime, timedelta, timezone

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.models import Scope
from contracts import EdgeStatus, Entity, Relationship, make_edge_id

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
ACCT, OTHER_ACCT = "111122223333", "999988887777"
API, OTHER_API = "iam:GetAccountAuthorizationDetails", "iam:ListRoles"


def h(n):
    return timedelta(hours=n)


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


def user(name, acct=ACCT):
    return Entity(entity_id=f"arn:aws:iam::{acct}:user/{name}", entity_type="iam_user",
                  name=name, account_id=acct, attributes={})


def group(name, acct=ACCT):
    return Entity(entity_id=f"arn:aws:iam::{acct}:group/{name}", entity_type="iam_group",
                  name=name, account_id=acct, attributes={})


def edge(src, dst, status=EdgeStatus.CONFIRMED):
    return Relationship(
        edge_id=make_edge_id(src.entity_id, "member_of", dst.entity_id, ""),
        source_id=src.entity_id, target_id=dst.entity_id,
        relation_type="member_of", discriminator="", status=status,
    )


def make_repo(entities, now=T0 + h(1), **kw):
    clock = Clock(now)
    repo = InMemoryGraphRepository(clock=clock, **kw)
    for e in entities:
        repo.upsert_entity(e)
    return repo, clock


def test_edge_turns_stale_exactly_at_window_and_version_changes():
    alice, dev = user("alice"), group("dev")
    repo, clock = make_repo([alice, dev])
    repo.upsert_edge(edge(alice, dev), observed_at=T0, source_api=API)

    clock.now = T0 + h(24) - timedelta(seconds=1)
    before = repo.snapshot()
    assert before.edges[0].status == EdgeStatus.CONFIRMED

    clock.now = T0 + h(24)
    after = repo.snapshot()
    assert after.edges[0].status == EdgeStatus.STALE
    assert after.version != before.version
    # raw read is unchanged; staleness is applied only in snapshots
    assert repo.get_edge(before.edges[0].edge_id).status == EdgeStatus.CONFIRMED


def test_version_is_stable_while_nothing_crosses_a_boundary():
    alice, dev = user("alice"), group("dev")
    repo, clock = make_repo([alice, dev])
    repo.upsert_edge(edge(alice, dev), observed_at=T0, source_api=API)
    v1 = repo.snapshot().version
    clock.now = T0 + h(10)
    assert repo.snapshot().version == v1


def test_window_none_disables_staleness():
    alice, dev = user("alice"), group("dev")
    repo, clock = make_repo([alice, dev], freshness_window=None)
    repo.upsert_edge(edge(alice, dev), observed_at=T0, source_api=API)
    clock.now = T0 + h(24 * 365)
    assert repo.snapshot().edges[0].status == EdgeStatus.CONFIRMED


def test_edge_without_observed_at_is_never_stale():
    alice, dev = user("alice"), group("dev")
    repo, clock = make_repo([alice, dev])
    repo.upsert_edge(edge(alice, dev))  # seed / direct write
    clock.now = T0 + h(24 * 365)
    assert repo.snapshot().edges[0].status == EdgeStatus.CONFIRMED


def test_unknown_is_not_overridden_by_stale():
    alice, dev = user("alice"), group("dev")
    repo, clock = make_repo([alice, dev])
    repo.upsert_edge(edge(alice, dev), observed_at=T0, source_api=API)
    repo.mark_scope_unknown(Scope(ACCT, API), at=T0 + h(1))
    clock.now = T0 + h(48)
    assert repo.snapshot().edges[0].status == EdgeStatus.UNKNOWN


def test_equal_timestamps_first_event_wins():
    alice, dev = user("alice"), group("dev")
    repo, _ = make_repo([alice, dev])
    repo.upsert_edge(edge(alice, dev, EdgeStatus.CONFIRMED), observed_at=T0, source_api=API)
    change = repo.upsert_edge(edge(alice, dev, EdgeStatus.INFERRED), observed_at=T0, source_api=API)
    assert change.changed is False
    assert repo.get_edge(edge(alice, dev).edge_id).status == EdgeStatus.CONFIRMED


def test_scope_unknown_only_touches_matching_edges():
    alice, bob = user("alice"), user("bob", OTHER_ACCT)
    g1, g2, g3, g4 = group("g1"), group("g2"), group("g3"), group("g4")
    repo, _ = make_repo([alice, bob, g1, g2, g3, g4])

    target = edge(alice, g1)
    other_account = edge(bob, g1)
    other_api = edge(alice, g2)
    invalidated = edge(alice, g3)
    unobserved = edge(alice, g4)

    repo.upsert_edge(target, observed_at=T0, source_api=API)
    repo.upsert_edge(other_account, observed_at=T0, source_api=API)
    repo.upsert_edge(other_api, observed_at=T0, source_api=OTHER_API)
    repo.upsert_edge(invalidated, observed_at=T0, source_api=API)
    repo.invalidate_edge(invalidated.edge_id, at=T0 + h(1))
    repo.upsert_edge(unobserved, source_api=API)  # no observed_at

    change = repo.mark_scope_unknown(Scope(ACCT, API), at=T0 + h(2))

    assert change.changed is True
    status = lambda e: repo.get_edge(e.edge_id).status
    assert status(target) == EdgeStatus.UNKNOWN
    assert status(other_account) == EdgeStatus.CONFIRMED
    assert status(other_api) == EdgeStatus.CONFIRMED
    assert status(invalidated) == EdgeStatus.INVALIDATED
    assert status(unobserved) == EdgeStatus.CONFIRMED


def test_stale_failure_report_is_ignored():
    alice, dev = user("alice"), group("dev")
    repo, _ = make_repo([alice, dev])
    e = edge(alice, dev)
    repo.upsert_edge(e, observed_at=T0 + h(3), source_api=API)
    change = repo.mark_scope_unknown(Scope(ACCT, API), at=T0 + h(2))  # older than observation
    assert change.changed is False
    assert repo.get_edge(e.edge_id).status == EdgeStatus.CONFIRMED
