"""Collector tests use botocore's Stubber, so no AWS account or network is needed."""
import json
from pathlib import Path
from urllib.parse import quote

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber  # noqa: E402

from backend.ingestion import collector  # noqa: E402
from backend.ingestion.collector import (  # noqa: E402
    ALL_FILTERS,
    READ_ONLY_POLICY,
    CollectionError,
    collect_account,
    detect_account_id,
    replace_account_id,
    save_dump,
)
from backend.ingestion.loader import load_account_file, parse_account  # noqa: E402
from backend.ingestion.snapshot import build_snapshot  # noqa: E402

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures" / "organization" / "scenario_01_passrole_escalation.json"
)
POLICY_KEYS = {"PolicyDocument", "Document", "AssumeRolePolicyDocument"}
ID_KEYS = {"UserId", "GroupId", "RoleId", "PolicyId"}  # real AWS ids are 16+ chars
OP = "get_account_authorization_details"


def aws_encode(value):
    """Make fixture data look like a real AWS response.

    AWS sends policy documents URL-encoded (botocore decodes them for us)
    and the stubber enforces real field rules, such as 16+ character ids.
    """
    if isinstance(value, dict):
        return {
            k: quote(json.dumps(v)) if k in POLICY_KEYS
            else v.ljust(16, "X") if k in ID_KEYS
            else aws_encode(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [aws_encode(v) for v in value]
    return value


def make_client():
    return boto3.client("iam", region_name="us-east-1",
                        aws_access_key_id="test", aws_secret_access_key="test")


def two_pages():
    data = aws_encode(json.loads(FIXTURE.read_text()))
    page1 = {"UserDetailList": data["UserDetailList"], "GroupDetailList": data["GroupDetailList"],
             "IsTruncated": True, "Marker": "m1"}
    page2 = {"RoleDetailList": data["RoleDetailList"], "Policies": data["Policies"], "IsTruncated": False}
    return page1, page2


def test_pages_are_merged_and_policies_decoded():
    client = make_client()
    page1, page2 = two_pages()
    with Stubber(client) as stub:
        stub.add_response(OP, page1, {"Filter": ALL_FILTERS})
        stub.add_response(OP, page2, {"Filter": ALL_FILTERS, "Marker": "m1"})
        dump = collect_account(client)
        stub.assert_no_pending_responses()
    assert [u["UserName"] for u in dump["UserDetailList"]] == ["alice", "bob"]
    assert len(dump["RoleDetailList"]) == 2
    # decoded into real dicts, which is what parse_account needs
    assert isinstance(dump["RoleDetailList"][0]["AssumeRolePolicyDocument"], dict)


def test_collected_dump_gives_the_same_graph_as_the_fixture():
    client = make_client()
    page1, page2 = two_pages()
    with Stubber(client) as stub:
        stub.add_response(OP, page1, {"Filter": ALL_FILTERS})
        stub.add_response(OP, page2, {"Filter": ALL_FILTERS, "Marker": "m1"})
        dump = collect_account(client)
    from datetime import datetime, timezone
    now = datetime(2026, 10, 14, tzinfo=timezone.utc)
    live = build_snapshot(parse_account(dump), created_at=now).snapshot
    expected = build_snapshot(load_account_file(FIXTURE), created_at=now).snapshot
    assert live.version == expected.version
    assert len(live.edges) == 14


def test_can_skip_aws_managed_policies():
    client = make_client()
    filters = [f for f in ALL_FILTERS if f != "AWSManagedPolicy"]
    with Stubber(client) as stub:
        stub.add_response(OP, {"IsTruncated": False}, {"Filter": filters})
        dump = collect_account(client, include_aws_managed=False)
    assert dump == {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}


def test_access_denied_gives_an_actionable_error():
    client = make_client()
    with Stubber(client) as stub:
        stub.add_client_error(OP, service_error_code="AccessDenied", http_status_code=403)
        with pytest.raises(CollectionError, match="GetAccountAuthorizationDetails"):
            collect_account(client)


def test_other_aws_errors_are_wrapped():
    client = make_client()
    with Stubber(client) as stub:
        stub.add_client_error(OP, service_error_code="ServiceFailure", http_status_code=500)
        with pytest.raises(CollectionError, match="ServiceFailure"):
            collect_account(client)


def test_missing_boto3_message(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("no boto3")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(CollectionError, match="pip install boto3"):
        collect_account()


def test_read_only_policy_allows_exactly_one_action():
    (statement,) = READ_ONLY_POLICY["Statement"]
    assert statement["Effect"] == "Allow"
    assert statement["Action"] == "iam:GetAccountAuthorizationDetails"


def test_collector_only_makes_the_one_read_call():
    client = make_client()
    calls = []
    client.meta.events.register("before-parameter-build.iam.*", lambda model, **kw: calls.append(model.name))
    with Stubber(client) as stub:
        stub.add_response(OP, {"IsTruncated": False}, {"Filter": ALL_FILTERS})
        collect_account(client)
    assert calls == ["GetAccountAuthorizationDetails"]


def test_save_dump_handles_datetimes_and_round_trips(tmp_path):
    from datetime import datetime, timezone
    data = json.loads(FIXTURE.read_text())
    data["UserDetailList"][0]["CreateDate"] = datetime(2026, 1, 1, tzinfo=timezone.utc)
    target = tmp_path / "nested" / "dump.json"
    save_dump(data, target)
    assert len(parse_account(json.loads(target.read_text())).users) == 2


def test_detect_and_replace_account_id():
    data = json.loads(FIXTURE.read_text())
    assert detect_account_id(data) == "111122223333"
    moved = replace_account_id(data, "111122223333", "999988887777")
    assert "111122223333" not in json.dumps(moved)
    assert "999988887777" in json.dumps(moved)
    assert detect_account_id({}) is None


def test_replace_account_id_rejects_bad_ids():
    with pytest.raises(ValueError):
        replace_account_id({}, "123", "111122223333")


def test_cli_writes_a_dump(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(collector, "collect_account", lambda **kw: json.loads(FIXTURE.read_text()))
    out = tmp_path / "d.json"
    assert collector.main(["--out", str(out), "--anonymize"]) == 0
    assert out.exists() and "2 users" in capsys.readouterr().out


def test_cli_reports_errors_without_a_traceback(tmp_path, monkeypatch, capsys):
    def boom(**kw):
        raise CollectionError("nope")
    monkeypatch.setattr(collector, "collect_account", boom)
    assert collector.main(["--out", str(tmp_path / "d.json")]) == 1
    assert "error: nope" in capsys.readouterr().err
