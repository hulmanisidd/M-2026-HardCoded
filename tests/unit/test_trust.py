from backend.ingestion.policy import parse_policy_document
from backend.ingestion.trust import (
    TrustMatch,
    trust_allows_principal,
    trust_allows_service,
)

ACCT = "111122223333"
ALICE = f"arn:aws:iam::{ACCT}:user/alice"
BOB = f"arn:aws:iam::{ACCT}:user/bob"


def trust(*statements):
    return parse_policy_document({"Version": "2012-10-17", "Statement": list(statements)})


def allow(principal, **extra):
    return {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole", **extra}


def test_named_user_is_direct():
    result = trust_allows_principal(trust(allow({"AWS": ALICE})), ALICE, ACCT)
    assert result.match is TrustMatch.DIRECT and not result.conditional


def test_other_user_is_not_trusted():
    result = trust_allows_principal(trust(allow({"AWS": ALICE})), BOB, ACCT)
    assert result.match is TrustMatch.NONE and not result.trusted


def test_account_root_is_delegated_to_identity_policy():
    result = trust_allows_principal(trust(allow({"AWS": f"arn:aws:iam::{ACCT}:root"})), BOB, ACCT)
    assert result.match is TrustMatch.ACCOUNT_DELEGATED


def test_bare_account_id_counts_as_root():
    result = trust_allows_principal(trust(allow({"AWS": ACCT})), BOB, ACCT)
    assert result.match is TrustMatch.ACCOUNT_DELEGATED


def test_other_accounts_root_does_not_match():
    other = "arn:aws:iam::999999999999:root"
    assert not trust_allows_principal(trust(allow({"AWS": other})), BOB, ACCT).trusted


def test_star_principal_is_direct():
    assert trust_allows_principal(trust(allow("*")), BOB, ACCT).match is TrustMatch.DIRECT


def test_direct_beats_delegated():
    stmts = trust(allow({"AWS": f"arn:aws:iam::{ACCT}:root"}), allow({"AWS": ALICE}))
    assert trust_allows_principal(stmts, ALICE, ACCT).match is TrustMatch.DIRECT


def test_condition_makes_result_conditional():
    stmts = trust(allow({"AWS": ALICE}, Condition={"StringEquals": {"sts:ExternalId": "x"}}))
    result = trust_allows_principal(stmts, ALICE, ACCT)
    assert result.match is TrustMatch.DIRECT and result.conditional


def test_unconditional_statement_wins_over_conditional_one():
    stmts = trust(
        allow({"AWS": ALICE}, Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}),
        allow({"AWS": ALICE}),
    )
    assert not trust_allows_principal(stmts, ALICE, ACCT).conditional


def test_explicit_deny_blocks():
    stmts = trust(
        allow({"AWS": f"arn:aws:iam::{ACCT}:root"}),
        {"Effect": "Deny", "Principal": {"AWS": BOB}, "Action": "sts:AssumeRole"},
    )
    assert trust_allows_principal(stmts, BOB, ACCT).match is TrustMatch.NONE


def test_conditional_deny_flags_conditional():
    stmts = trust(
        allow({"AWS": ALICE}),
        {"Effect": "Deny", "Principal": {"AWS": ALICE}, "Action": "sts:AssumeRole",
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
    )
    result = trust_allows_principal(stmts, ALICE, ACCT)
    assert result.match is TrustMatch.DIRECT and result.conditional


def test_other_actions_are_ignored():
    stmts = trust({"Effect": "Allow", "Principal": {"AWS": ALICE}, "Action": "sts:TagSession"})
    assert not trust_allows_principal(stmts, ALICE, ACCT).trusted


def test_wildcard_action_in_trust_counts():
    stmts = trust({"Effect": "Allow", "Principal": {"AWS": ALICE}, "Action": "sts:*"})
    assert trust_allows_principal(stmts, ALICE, ACCT).trusted


def test_not_principal_allow_is_never_a_sure_thing():
    stmts = trust({"Effect": "Allow", "NotPrincipal": {"AWS": BOB}, "Action": "sts:AssumeRole"})
    result = trust_allows_principal(stmts, ALICE, ACCT)
    assert result.trusted and result.conditional
    assert not trust_allows_principal(stmts, BOB, ACCT).trusted


def test_service_trust():
    stmts = trust(allow({"Service": "lambda.amazonaws.com"}))
    assert trust_allows_service(stmts, "lambda.amazonaws.com").match is TrustMatch.DIRECT
    assert not trust_allows_service(stmts, "ec2.amazonaws.com").trusted


def test_service_trust_with_condition_is_conditional():
    stmts = trust(allow({"Service": "lambda.amazonaws.com"},
                        Condition={"StringEquals": {"aws:SourceAccount": ACCT}}))
    assert trust_allows_service(stmts, "lambda.amazonaws.com").conditional


def test_fixture_roles():
    import json
    from pathlib import Path

    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "organization" / "scenario_01_passrole_escalation.json"
    roles = {r["RoleName"]: r for r in json.loads(fixture.read_text())["RoleDetailList"]}
    build = parse_policy_document(roles["build-role"]["AssumeRolePolicyDocument"])
    admin = parse_policy_document(roles["admin-role"]["AssumeRolePolicyDocument"])
    assert trust_allows_principal(build, ALICE, ACCT).match is TrustMatch.ACCOUNT_DELEGATED
    assert not trust_allows_principal(admin, ALICE, ACCT).trusted
    assert trust_allows_service(admin, "lambda.amazonaws.com").trusted
