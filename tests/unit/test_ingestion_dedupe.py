"""A dump that lists the same principal or policy twice (for example, pages
that overlap during a collection) must not crash ingestion. The first copy
wins, and we say so in the warnings."""
import copy
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.ingestion.edges import build_edges
from backend.ingestion.events import emit_collection_events
from backend.ingestion.loader import parse_account
from backend.ingestion.normalizer import normalize_entities
from backend.ingestion.snapshot import build_snapshot

S1 = Path(__file__).resolve().parents[2] / "fixtures" / "organization" / "scenario_01_passrole_escalation.json"
NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)
ALICE = "arn:aws:iam::111122223333:user/alice"


def clean():
    return json.loads(S1.read_text())


def with_duplicate(key, index=0, **changes):
    data = clean()
    twin = copy.deepcopy(data[key][index])
    twin.update(changes)
    data[key].append(twin)
    return data


def test_clean_data_has_no_duplicates_and_no_warning():
    account = parse_account(clean())
    assert account.duplicate_arns == ()
    assert not [w for w in build_snapshot(account, created_at=NOW).warnings if "duplicate" in w]


def test_duplicate_user_does_not_crash_build_snapshot():
    result = build_snapshot(parse_account(with_duplicate("UserDetailList")), created_at=NOW)
    assert len(result.snapshot.entities) == 8 and len(result.snapshot.edges) == 14


def test_duplicate_is_reported_in_warnings():
    result = build_snapshot(parse_account(with_duplicate("UserDetailList")), created_at=NOW)
    assert any("duplicate" in w and ALICE in w for w in result.warnings)


def test_first_copy_wins():
    # the second copy claims a group that does not exist; if it were used we would get a warning
    account = parse_account(with_duplicate("UserDetailList", GroupList=["ghost"]))
    assert len(account.users) == 2
    assert account.users[0].group_names == ("developers",)
    assert not [w for w in build_snapshot(account, created_at=NOW).warnings if "ghost" in w]


def test_duplicates_in_every_list_are_handled():
    data = clean()
    for key in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"):
        data[key].append(copy.deepcopy(data[key][0]))
    account = parse_account(data)
    assert len(account.duplicate_arns) == 4
    result = build_snapshot(account, created_at=NOW)
    assert len(result.snapshot.entities) == 8 and len(result.snapshot.edges) == 14


def test_event_path_does_not_emit_duplicate_upserts():
    account = parse_account(with_duplicate("RoleDetailList"))
    events = emit_collection_events(normalize_entities(account), build_edges(account).edges,
                                    account_id="111122223333", occurred_at=NOW)
    upserts = [e for e in events if e.event_type == "ENTITY_UPSERTED"]
    assert len(upserts) == 8
    assert len({e.payload["entity"]["entity_id"] for e in upserts}) == 8


def test_deduped_graph_equals_clean_graph():
    clean_snapshot = build_snapshot(parse_account(clean()), created_at=NOW).snapshot
    dup_snapshot = build_snapshot(parse_account(with_duplicate("UserDetailList")), created_at=NOW).snapshot
    assert dup_snapshot.version == clean_snapshot.version
