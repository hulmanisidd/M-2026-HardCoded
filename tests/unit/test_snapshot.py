from datetime import datetime, timezone
from pathlib import Path

from backend.ingestion.loader import load_account_file, parse_account
from backend.ingestion.snapshot import build_snapshot, build_snapshot_from_file
from contracts.relationships import EdgeStatus

ORG = Path(__file__).resolve().parents[2] / "fixtures" / "organization"
S1 = ORG / "scenario_01_passrole_escalation.json"
S2 = ORG / "scenario_02_role_chain.json"
NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)
ALICE = "arn:aws:iam::111122223333:user/alice"


def test_builds_snapshot_with_entities_and_edges():
    result = build_snapshot_from_file(S1, created_at=NOW)
    assert len(result.snapshot.entities) == 8
    assert len(result.snapshot.edges) == 14
    assert result.warnings == ()


def test_same_data_gives_same_version():
    a = build_snapshot_from_file(S1, created_at=NOW).snapshot
    b = build_snapshot_from_file(S1, created_at=NOW).snapshot
    assert a.version == b.version and a.version.startswith("ing-")


def test_different_data_gives_different_version():
    assert (build_snapshot_from_file(S1, created_at=NOW).snapshot.version
            != build_snapshot_from_file(S2, created_at=NOW).snapshot.version)


def test_edge_status_changes_the_version():
    acct = load_account_file(S1)
    a = build_snapshot(acct, created_at=NOW).snapshot.version
    b = build_snapshot(acct, created_at=NOW, policy_edge_status=EdgeStatus.CONFIRMED).snapshot.version
    assert a != b


def test_explicit_version_wins():
    assert build_snapshot(load_account_file(S1), created_at=NOW, version="v9").snapshot.version == "v9"


def test_default_created_at_is_timezone_aware():
    assert build_snapshot(parse_account({})).snapshot.created_at.tzinfo is not None


def test_empty_account_gives_empty_graph():
    snap = build_snapshot(parse_account({}), created_at=NOW).snapshot
    assert snap.entities == () and snap.edges == ()


def test_warnings_are_passed_through():
    acct = parse_account({"UserDetailList": [{
        "UserName": "u", "UserId": "x", "Arn": "arn:aws:iam::111122223333:user/u",
        "GroupList": ["ghost"]}]})
    assert any("ghost" in w for w in build_snapshot(acct, created_at=NOW).warnings)


def test_fork_removing_an_edge_removes_the_hop():
    """This is how remediation will test a fix: remove an edge, look again."""
    snap = build_snapshot_from_file(S1, created_at=NOW).snapshot
    assume = next(e for e in snap.get_neighbors(ALICE) if e.relation_type == "can_assume")
    fixed = snap.fork([assume.edge_id])
    assert not [e for e in fixed.get_neighbors(ALICE) if e.relation_type == "can_assume"]
    assert len(fixed.edges) == len(snap.edges) - 1
