from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from contracts.events import NormalizedEvent


def make_event(**overrides):
    data = {
        "event_id": "evt-1",
        "event_type": "AttachRolePolicy",
        "source": "cloudtrail",
        "occurred_at": datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc),
    }
    data.update(overrides)
    return NormalizedEvent(**data)


def test_aware_datetime_is_accepted():
    e = make_event()
    assert e.occurred_at.tzinfo is not None
    assert e.payload == {}


def test_naive_datetime_is_rejected():
    with pytest.raises(ValidationError):
        make_event(occurred_at=datetime(2026, 10, 14, 12, 0))


def test_iso_string_with_z_is_parsed():
    e = make_event(occurred_at="2026-10-14T12:00:00Z")
    assert e.occurred_at.utcoffset().total_seconds() == 0


def test_empty_event_id_is_rejected():
    with pytest.raises(ValidationError):
        make_event(event_id="")


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        make_event(colour="red")
