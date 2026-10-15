from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from contracts.relationships import EdgeStatus, Relationship, make_edge_id
from contracts.vocab import RelationType

UTC = timezone.utc


def make_rel(**overrides):
    data = {
        "source_id": "user-a",
        "target_id": "role-b",
        "relation_type": RelationType.CAN_ASSUME,
    }
    data.update(overrides)
    return Relationship(**data)


def test_edge_id_is_derived_and_deterministic():
    r1, r2 = make_rel(), make_rel()
    assert r1.edge_id == r2.edge_id
    assert r1.edge_id == make_edge_id("user-a", RelationType.CAN_ASSUME, "role-b")


def test_edge_id_ignores_status():
    assert make_rel(status="confirmed").edge_id == make_rel(status="stale").edge_id


def test_parallel_edges_get_distinct_ids():
    a = make_rel(discriminator="policy-1")
    b = make_rel(discriminator="policy-2")
    assert a.edge_id != b.edge_id


def test_explicit_edge_id_is_kept():
    assert make_rel(edge_id="custom-1").edge_id == "custom-1"


def test_default_status_is_unknown():
    assert make_rel().status is EdgeStatus.UNKNOWN


def test_window_must_be_ordered():
    with pytest.raises(ValidationError):
        make_rel(
            valid_from=datetime(2026, 10, 14, tzinfo=UTC),
            valid_until=datetime(2026, 10, 13, tzinfo=UTC),
        )


def test_naive_datetime_is_rejected():
    with pytest.raises(ValidationError):
        make_rel(valid_from=datetime(2026, 10, 14))


def test_unknown_relation_type_is_rejected():
    with pytest.raises(ValidationError):
        make_rel(relation_type="teleports_to")


def test_evidence_list_is_coerced_to_tuple():
    assert make_rel(evidence_ids=["ev-1", "ev-2"]).evidence_ids == ("ev-1", "ev-2")