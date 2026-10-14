"""GraphUpdater against P1's agreed event shapes."""
from datetime import datetime, timedelta, timezone
from itertools import permutations

import pytest

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.models import ChangeKind
from backend.graph.updater import GraphUpdater, MissingEndpointError, RejectedEvent
from contracts import EdgeStatus, NormalizedEvent, RelationType, make_edge_id

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
ACCT = "111122223333"
API = "iam:GetAccountAuthorizationDetails"
ALICE = f"arn:aws:iam::{ACCT}:user/alice"
DEV = f"arn:aws:iam::{ACCT}:group/developers"
EDGE_ID = make_edge_id(ALICE, "member_of", DEV, "")


def h(n):
    return timedelta(hours=n)


_n = [0]


def ev(event_type, at, payload, source=API):
    _n[0] += 1
    return NormalizedEvent(
        event_id=f"ev_{_n[0]}",
        event_type=event_type,
        source=source,
        occurred_at=at,
        ingested_at=at + timedelta(seconds=2),
        payload={"collection_run_id": "run", **payload},
    )


def entity_ev(entity_id, typ, name, at=T0):
    return ev(
        "ENTITY_UPSERTED",
        at,
        {
            "entity": {
                "entity_id": entity_id,
                "entity_type": typ,
                "name": name,
                "criticality": None,  # P1 sends null for unclassified
                "account_id": ACCT,
                "attributes": {},
            }
        },
    )


def obs_ev(at, status="confirmed", edge_id=EDGE_ID):
    return ev(
        "EDGE_OBSERVED",
        at,
        {
            "edge": {
                "edge_id": edge_id,
                "source_id": ALICE,
                "relation_type": "member_of",
                "target_id": DEV,
                "discriminator": "",
                "status": status,
                "conditions": {},
                "evidence_ids": ["ev-src-001"],
                "observed_at": at.isoformat(),  # contract PR pending
            }
        },
    )


def removed_ev(at):
    return ev(
        "EDGE_REMOVED",
        at,
        {
            "edge_id": EDGE_ID,
            "source_id": ALICE,
            "relation_type": "member_of",
            "target_id": DEV,
            "discriminator": "",
        },
    )


def failed_ev(at):
    return ev(
        "COLLECTION_FAILED",
        at,
        {
            "scope": {"account_id": ACCT, "source_api": API},
            "reason": "throttled",
            "partial": True,
            "last_success_at": T0.isoformat(),
        },
    )


def completed_ev(at):
    return ev(
        "COLLECTION_COMPLETED",
        at,
        {"scope": {"account_id": ACCT, "source_api": API}},
    )


def _setup():
    repo = InMemoryGraphRepository(clock=lambda: T0 + h(1))
    up = GraphUpdater(repo)
    up.apply_event(entity_ev(ALICE, "iam_user", "alice"))
    up.apply_event(entity_ev(DEV, "iam_group", "developers"))
    return repo, up


def _status(repo):
    return repo.get_edge(EDGE_ID).status


def test_p1_sample_shapes_are_accepted():
    repo, up = _setup()
    change = up.apply_event(obs_ev(T0))
    assert change.kind == ChangeKind.EDGE_ADDED and change.changed is True
    edge = repo.get_edge(EDGE_ID)
    assert edge.relation_type == RelationType.MEMBER_OF
    assert edge.status == EdgeStatus.CONFIRMED


def test_identical_redelivery_is_noop():
    repo, up = _setup()
    e = obs_ev(T0)
    up.apply_event(e)
    v = repo.snapshot().version
    assert up.apply_event(e).changed is False
    assert repo.snapshot().version == v


def test_older_entity_event_does_not_regress_entity():
    repo, up = _setup()
    newer = entity_ev(ALICE, "iam_user", "alice-renamed", at=T0 + h(2))
    older = entity_ev(ALICE, "iam_user", "alice-old", at=T0 + h(1))
    up.apply_event(newer)
    assert up.apply_event(older).changed is False
    assert repo.get_entity(ALICE).name == "alice-renamed"


def test_rejects_edge_id_mismatch():
    _, up = _setup()
    with pytest.raises(RejectedEvent, match="edge_id mismatch"):
        up.apply_event(obs_ev(T0, edge_id="e_0000000000000000"))


def test_rejects_non_p1_statuses():
    _, up = _setup()
    for status in ("stale", "unknown", "invalidated"):
        with pytest.raises(RejectedEvent):
            up.apply_event(obs_ev(T0, status=status))


def test_rejects_unknown_event_type_and_bad_payload():
    _, up = _setup()
    with pytest.raises(RejectedEvent):
        up.apply_event(ev("SOMETHING_ELSE", T0, {}))
    with pytest.raises(RejectedEvent):
        up.apply_event(ev("EDGE_OBSERVED", T0, {}))
    with pytest.raises(RejectedEvent):
        up.apply_event(ev("COLLECTION_FAILED", T0, {"scope": {"account_id": ACCT}}))


def test_missing_endpoint_is_retryable():
    repo = InMemoryGraphRepository(clock=lambda: T0 + h(1))
    up = GraphUpdater(repo)
    e = obs_ev(T0)
    with pytest.raises(MissingEndpointError):
        up.apply_event(e)
    up.apply_event(entity_ev(ALICE, "iam_user", "alice"))
    up.apply_event(entity_ev(DEV, "iam_group", "developers"))
    assert up.apply_event(e).changed is True


def test_removal_invalidates_and_old_replay_is_ignored():
    repo, up = _setup()
    up.apply_event(obs_ev(T0))
    assert up.apply_event(removed_ev(T0 + h(2))).changed is True
    assert _status(repo) == EdgeStatus.INVALIDATED
    assert up.apply_event(obs_ev(T0 + h(1))).changed is False  # old replay
    assert _status(repo) == EdgeStatus.INVALIDATED
    assert up.apply_event(obs_ev(T0 + h(3))).changed is True  # fresh re-grant
    assert _status(repo) == EdgeStatus.CONFIRMED


def test_removal_before_observation_leaves_tombstone():
    repo, up = _setup()
    up.apply_event(removed_ev(T0 + h(2)))
    assert _status(repo) == EdgeStatus.INVALIDATED
    assert up.apply_event(obs_ev(T0)).changed is False
    assert _status(repo) == EdgeStatus.INVALIDATED


def test_final_status_is_independent_of_delivery_order():
    events = [obs_ev(T0), obs_ev(T0 + h(1)), removed_ev(T0 + h(2))]
    versions = set()
    for order in permutations(events):
        repo, up = _setup()
        for e in order:
            up.apply_event(e)
        assert _status(repo) == EdgeStatus.INVALIDATED
        versions.add(repo.snapshot().edges[0].status)
    assert versions == {EdgeStatus.INVALIDATED}


def test_failed_collection_marks_unknown_until_newer_observation():
    repo, up = _setup()
    up.apply_event(obs_ev(T0))
    change = up.apply_event(failed_ev(T0 + h(2)))
    assert change.kind == ChangeKind.SCOPE_MARKED_UNKNOWN and change.changed is True
    assert _status(repo) == EdgeStatus.UNKNOWN
    assert repo.snapshot().edges[0].status == EdgeStatus.UNKNOWN

    up.apply_event(obs_ev(T0 + h(1)))  # older run arrives late: still unknown
    assert _status(repo) == EdgeStatus.UNKNOWN

    done = up.apply_event(completed_ev(T0 + h(3)))
    assert done.kind == ChangeKind.COLLECTION_COMPLETED and done.changed is False
    up.apply_event(obs_ev(T0 + h(3)))  # re-emitted in the completed run
    assert _status(repo) == EdgeStatus.CONFIRMED


def test_entity_removed_keeps_entity():
    repo, up = _setup()
    change = up.apply_event(ev("ENTITY_REMOVED", T0 + h(1), {"entity_id": ALICE}))
    assert change.changed is False
    assert repo.get_entity(ALICE) is not None
