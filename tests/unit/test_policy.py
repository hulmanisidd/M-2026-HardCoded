import pytest

from backend.ingestion.policy import (
    Decision,
    Effect,
    PolicyParseError,
    evaluate,
    parse_policy_document,
    wildcard_match,
)

ROLE = "arn:aws:iam::111122223333:role/admin-role"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def run(document, action, resource="*"):
    return evaluate(parse_policy_document(document), action, resource)


# --- parsing ---

def test_single_statement_dict_and_string_shortcuts():
    stmts = parse_policy_document(
        {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}
    )
    assert len(stmts) == 1
    assert stmts[0].actions == ("s3:GetObject",)
    assert stmts[0].effect is Effect.ALLOW


def test_missing_document_is_no_statements():
    assert parse_policy_document(None) == ()


@pytest.mark.parametrize("bad", [
    {"Version": "2012-10-17"},
    {"Statement": [{"Action": "s3:*", "Resource": "*"}]},
    {"Statement": [{"Effect": "Maybe", "Action": "s3:*", "Resource": "*"}]},
    {"Statement": [{"Effect": "Allow", "Resource": "*"}]},
    {"Statement": [{"Effect": "Allow", "Action": 5, "Resource": "*"}]},
])
def test_malformed_policies_raise(bad):
    with pytest.raises(PolicyParseError):
        parse_policy_document(bad)


def test_principal_forms():
    stmts = parse_policy_document({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
         "Action": "sts:AssumeRole"},
    ]})
    assert stmts[0].principals == {"AWS": ("*",)}
    assert stmts[1].principals == {"Service": ("lambda.amazonaws.com",)}


# --- wildcards ---

def test_wildcards():
    assert wildcard_match("iam:*", "iam:PassRole", True)
    assert wildcard_match("iam:Pass*", "iam:PassRole", True)
    assert wildcard_match("*", "anything:at-all", True)
    assert wildcard_match("s3:Get?bject", "s3:GetObject", True)
    assert not wildcard_match("iam:Pass*", "iam:CreateRole", True)


def test_regex_characters_are_literal():
    assert not wildcard_match("arn:aws:s3:::a.b", "arn:aws:s3:::aXb")


def test_actions_ignore_case_resources_do_not():
    allow = doc({"Effect": "Allow", "Action": "IAM:passrole", "Resource": ROLE})
    assert run(allow, "iam:PassRole", ROLE).allowed
    assert not run(allow, "iam:PassRole", ROLE.upper()).allowed


# --- evaluation ---

def test_allow_matching_action_and_resource():
    result = run(doc({"Effect": "Allow", "Action": "iam:PassRole", "Resource": ROLE}),
                 "iam:PassRole", ROLE)
    assert result.decision is Decision.ALLOW
    assert result.conditional is False


def test_wrong_resource_is_implicit_deny():
    allow = doc({"Effect": "Allow", "Action": "iam:PassRole", "Resource": ROLE})
    result = run(allow, "iam:PassRole", "arn:aws:iam::111122223333:role/other")
    assert result.decision is Decision.IMPLICIT_DENY


def test_explicit_deny_beats_allow():
    policy = doc(
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Sid": "NoPass", "Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
    )
    result = run(policy, "iam:PassRole", ROLE)
    assert result.decision is Decision.DENY
    assert result.matched_sids == ("NoPass",)
    assert run(policy, "s3:GetObject", "arn:aws:s3:::b/k").allowed


def test_conditional_allow_is_flagged():
    policy = doc({"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*",
                  "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}})
    result = run(policy, "sts:AssumeRole", ROLE)
    assert result.allowed and result.conditional


def test_sure_allow_plus_conditional_allow_is_not_conditional():
    policy = doc(
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*",
         "Condition": {"Bool": {"aws:SecureTransport": "true"}}},
    )
    assert run(policy, "sts:AssumeRole", ROLE).conditional is False


def test_conditional_deny_makes_allow_conditional():
    policy = doc(
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:*", "Resource": "*",
         "Condition": {"StringNotEquals": {"aws:RequestedRegion": "ap-south-1"}}},
    )
    result = run(policy, "iam:PassRole", ROLE)
    assert result.allowed and result.conditional


def test_not_action_allow_covers_everything_else():
    policy = doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert run(policy, "s3:GetObject", "arn:aws:s3:::b/k").allowed
    assert run(policy, "iam:PassRole", ROLE).decision is Decision.IMPLICIT_DENY


def test_not_resource():
    policy = doc({"Effect": "Allow", "Action": "s3:GetObject",
                  "NotResource": "arn:aws:s3:::secret/*"})
    assert run(policy, "s3:GetObject", "arn:aws:s3:::public/a").allowed
    assert not run(policy, "s3:GetObject", "arn:aws:s3:::secret/a").allowed


def test_policy_variable_treated_as_wildcard():
    policy = doc({"Effect": "Allow", "Action": "s3:GetObject",
                  "Resource": "arn:aws:s3:::home/${aws:username}/*"})
    assert run(policy, "s3:GetObject", "arn:aws:s3:::home/alice/file").allowed


def test_empty_policy_denies():
    assert run(None, "s3:GetObject").decision is Decision.IMPLICIT_DENY
