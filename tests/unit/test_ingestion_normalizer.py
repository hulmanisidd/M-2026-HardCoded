from pathlib import Path

import pytest

from backend.ingestion.loader import load_account_file, parse_account
from backend.ingestion.normalizer import (
    account_id_from_arn,
    inline_policy_id,
    normalize_entities,
)
from contracts.graph import GraphSnapshot
from contracts.vocab import NodeType
from datetime import datetime, timezone

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures" / "organization" / "scenario_01_passrole_escalation.json"
)
ALICE = "arn:aws:iam::111122223333:user/alice"
BUILD_ROLE = "arn:aws:iam::111122223333:role/build-role"


@pytest.fixture(scope="module")
def entities():
    return normalize_entities(load_account_file(FIXTURE))


def by_id(entities, entity_id):
    return next(e for e in entities if e.entity_id == entity_id)


def test_node_counts_by_type(entities):
    counts = {}
    for e in entities:
        counts[e.entity_type] = counts.get(e.entity_type, 0) + 1
    assert counts == {
        NodeType.IAM_USER: 2,
        NodeType.IAM_GROUP: 1,
        NodeType.IAM_ROLE: 2,
        NodeType.IAM_POLICY: 3,  # 1 inline (group) + 2 managed
    }


def test_user_entity_fields(entities):
    alice = by_id(entities, ALICE)
    assert alice.name == "alice"
    assert alice.account_id == "111122223333"
    assert alice.attributes["tags"] == {"team": "platform"}
    assert alice.attributes["permissions_boundary"] is None


def test_role_keeps_trust_policy(entities):
    role = by_id(entities, BUILD_ROLE)
    assert role.attributes["trust_policy"]["Statement"][0]["Action"] == "sts:AssumeRole"


def test_inline_policy_gets_synthetic_id(entities):
    group_arn = "arn:aws:iam::111122223333:group/developers"
    policy = by_id(entities, inline_policy_id(group_arn, "AssumeBuildRole"))
    assert policy.attributes["inline"] is True
    assert policy.attributes["owner_arn"] == group_arn


def test_managed_policy_uses_default_version_document(entities):
    policy = by_id(entities, "arn:aws:iam::111122223333:policy/BuildPolicy")
    assert "iam:PassRole" in policy.attributes["document"]["Statement"][0]["Action"]


def test_aws_managed_policy_has_no_account_id(entities):
    admin = by_id(entities, "arn:aws:iam::aws:policy/AdministratorAccess")
    assert admin.account_id is None


def test_output_is_deterministic():
    first = normalize_entities(load_account_file(FIXTURE))
    second = normalize_entities(load_account_file(FIXTURE))
    assert first == second


def test_entities_fit_in_a_graph_snapshot(entities):
    graph = GraphSnapshot(
        version="v1",
        created_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
        entities=entities,
    )
    assert graph.get_entity(ALICE) is not None


def test_empty_account_is_valid():
    assert normalize_entities(parse_account({})) == ()


def test_account_id_from_arn():
    assert account_id_from_arn("arn:aws:iam::aws:policy/X") is None
    assert account_id_from_arn("arn:aws:iam::123456789012:role/r") == "123456789012"
