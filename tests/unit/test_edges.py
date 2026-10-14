from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.ingestion.edges import build_edges
from backend.ingestion.loader import load_account_file, parse_account
from backend.ingestion.normalizer import normalize_entities
from contracts.graph import GraphSnapshot
from contracts.paths import Feasibility
from contracts.relationships import EdgeStatus
from contracts.vocab import RelationType as R

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures" / "organization" / "scenario_01_passrole_escalation.json"
)
A = "arn:aws:iam::111122223333"


def names(result):
    short = lambda s: s.split("/")[-1].split("#")[-1]
    return {(short(e.source_id), str(e.relation_type), short(e.target_id)) for e in result.edges}


def find(result, source, relation, target):
    for e in result.edges:
        if (e.source_id.endswith(source) and e.relation_type == relation
                and e.target_id.endswith(target)):
            return e
    return None


# ---- tiny account builders ------------------------------------------------

def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def user(name, *, policies=(), groups=()):
    return {"UserName": name, "UserId": f"ID{name}", "Arn": f"{A}:user/{name}",
            "GroupList": list(groups),
            "UserPolicyList": [{"PolicyName": f"p{i}", "PolicyDocument": d}
                               for i, d in enumerate(policies)]}


def role(name, trust, *, policies=()):
    return {"RoleName": name, "RoleId": f"ID{name}", "Arn": f"{A}:role/{name}",
            "AssumeRolePolicyDocument": trust,
            "RolePolicyList": [{"PolicyName": f"p{i}", "PolicyDocument": d}
                               for i, d in enumerate(policies)]}


ROOT_TRUST = doc({"Effect": "Allow", "Principal": {"AWS": f"{A}:root"}, "Action": "sts:AssumeRole"})
LAMBDA_TRUST = doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"})


def account(users=(), roles=(), groups=(), policies=()):
    return parse_account({"UserDetailList": list(users), "RoleDetailList": list(roles),
                          "GroupDetailList": list(groups), "Policies": list(policies)})


# ---- scenario 1 -----------------------------------------------------------

def test_scenario_01_exact_edges():
    result = build_edges(load_account_file(FIXTURE))
    assert result.warnings == ()
    assert names(result) == {
        ("alice", "member_of", "developers"),
        ("developers", "has_policy", "AssumeBuildRole"),
        ("build-role", "has_policy", "BuildPolicy"),
        ("admin-role", "has_policy", "AdministratorAccess"),
        ("alice", "can_assume", "build-role"),
        ("admin-role", "can_assume", "build-role"),
        ("build-role", "can_pass_role", "admin-role"),
        ("admin-role", "can_pass_role", "admin-role"),
        *{("admin-role", "can_modify_policy", t)
          for t in ("alice", "bob", "developers", "build-role", "admin-role", "BuildPolicy")},
    }


def test_bob_has_no_outgoing_derived_edges():
    result = build_edges(load_account_file(FIXTURE))
    assert not [e for e in result.edges if e.source_id.endswith("user/bob")]


def test_observed_edges_confirmed_derived_inferred():
    result = build_edges(load_account_file(FIXTURE))
    for e in result.edges:
        expected = (EdgeStatus.CONFIRMED if e.relation_type in (R.MEMBER_OF, R.HAS_POLICY)
                    else EdgeStatus.INFERRED)
        assert e.status is expected


def test_status_for_derived_edges_is_configurable():
    result = build_edges(load_account_file(FIXTURE), policy_edge_status=EdgeStatus.CONFIRMED)
    edge = find(result, "user/alice", R.CAN_ASSUME, "build-role")
    assert edge.status is EdgeStatus.CONFIRMED


def test_evidence_points_at_the_granting_policies():
    edge = find(build_edges(load_account_file(FIXTURE)), "user/alice", R.CAN_ASSUME, "build-role")
    assert f"{A}:group/developers#inline/AssumeBuildRole" in edge.evidence_ids
    assert f"{A}:role/build-role" in edge.evidence_ids  # the trust policy lives here


def test_edges_and_entities_form_a_valid_snapshot():
    acct = load_account_file(FIXTURE)
    graph = GraphSnapshot(
        version="v1", created_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
        entities=normalize_entities(acct), edges=build_edges(acct).edges,
    )
    alice = f"{A}:user/alice"
    assert [graph.get_entity(e.target_id).name for e in graph.get_neighbors(alice)
            if e.relation_type == R.CAN_ASSUME] == ["build-role"]


def test_output_is_deterministic():
    acct = load_account_file(FIXTURE)
    assert build_edges(acct).edges == build_edges(acct).edges


def test_inferred_edges_are_conditional_for_the_path_engine():
    acct = load_account_file(FIXTURE)
    graph = GraphSnapshot(
        version="v1", created_at=datetime(2026, 10, 14, tzinfo=timezone.utc),
        entities=normalize_entities(acct), edges=build_edges(acct).edges,
    )
    edge = find(build_edges(acct), "user/alice", R.CAN_ASSUME, "build-role")
    assert graph.check_transition(edge.edge_id, {}).status is Feasibility.CONDITIONAL


# ---- CAN_ASSUME -----------------------------------------------------------

def test_assume_needs_identity_policy_when_trust_is_account_root():
    acct = account(users=[user("u")], roles=[role("r", ROOT_TRUST)])
    assert find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r") is None


def test_assume_with_both_sides():
    acct = account(users=[user("u", policies=[doc(allow("sts:AssumeRole", f"{A}:role/r"))])],
                   roles=[role("r", ROOT_TRUST)])
    assert find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r") is not None


def test_direct_trust_needs_no_identity_policy():
    trust = doc({"Effect": "Allow", "Principal": {"AWS": f"{A}:user/u"}, "Action": "sts:AssumeRole"})
    acct = account(users=[user("u")], roles=[role("r", trust)])
    assert find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r") is not None


def test_identity_deny_blocks_direct_trust():
    trust = doc({"Effect": "Allow", "Principal": {"AWS": f"{A}:user/u"}, "Action": "sts:AssumeRole"})
    deny = doc({"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"})
    acct = account(users=[user("u", policies=[deny])], roles=[role("r", trust)])
    assert find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r") is None


def test_wrong_resource_does_not_assume():
    acct = account(users=[user("u", policies=[doc(allow("sts:AssumeRole", f"{A}:role/other"))])],
                   roles=[role("r", ROOT_TRUST), role("other", doc())])
    assert find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r") is None


def test_conditional_identity_policy_marks_edge_conditional():
    cond = allow("sts:AssumeRole", f"{A}:role/r",
                 Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})
    acct = account(users=[user("u", policies=[doc(cond)])], roles=[role("r", ROOT_TRUST)])
    edge = find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r")
    assert edge.conditions == {"unevaluated_conditions": ["identity_policy"]}


def test_a_role_does_not_assume_itself():
    acct = account(roles=[role("r", ROOT_TRUST, policies=[doc(allow("sts:AssumeRole"))])])
    assert find(build_edges(acct), "role/r", R.CAN_ASSUME, "role/r") is None


# ---- CAN_PASS_ROLE --------------------------------------------------------

def pass_account(policy):
    return account(users=[user("u", policies=[policy])], roles=[role("r", LAMBDA_TRUST)])


def test_pass_role_with_launch_permission():
    acct = pass_account(doc(allow(["iam:PassRole", "lambda:CreateFunction"])))
    edge = find(build_edges(acct), "user/u", R.CAN_PASS_ROLE, "role/r")
    assert edge is not None and edge.conditions == {}


def test_pass_role_without_launch_permission_is_not_an_edge():
    acct = pass_account(doc(allow("iam:PassRole")))
    assert find(build_edges(acct), "user/u", R.CAN_PASS_ROLE, "role/r") is None


def test_launch_permission_without_pass_role_is_not_an_edge():
    acct = pass_account(doc(allow("lambda:CreateFunction")))
    assert find(build_edges(acct), "user/u", R.CAN_PASS_ROLE, "role/r") is None


def test_role_no_service_trusts_is_not_passable():
    acct = account(users=[user("u", policies=[doc(allow(["iam:PassRole", "lambda:CreateFunction"]))])],
                   roles=[role("r", ROOT_TRUST)])
    assert find(build_edges(acct), "user/u", R.CAN_PASS_ROLE, "role/r") is None


def test_resource_scoped_launch_is_flagged_not_dropped():
    policy = doc(allow("iam:PassRole"), allow("lambda:CreateFunction", f"{A}:function:only-this"))
    edge = find(build_edges(pass_account(policy)), "user/u", R.CAN_PASS_ROLE, "role/r")
    assert edge.conditions["launch_action_resource_scope_unchecked"] is True
    assert "unevaluated_conditions" in edge.conditions


def test_pass_role_scoped_to_other_role_is_not_an_edge():
    policy = doc(allow("iam:PassRole", f"{A}:role/other"), allow("lambda:CreateFunction"))
    assert find(build_edges(pass_account(policy)), "user/u", R.CAN_PASS_ROLE, "role/r") is None


# ---- CAN_MODIFY_POLICY ----------------------------------------------------

@pytest.mark.parametrize("action,target", [
    ("iam:PutUserPolicy", "user/victim"),
    ("iam:AttachRolePolicy", "role/r"),
    ("iam:UpdateAssumeRolePolicy", "role/r"),
    ("iam:PutGroupPolicy", "group/g"),
    ("iam:AddUserToGroup", "group/g"),
])
def test_modify_actions(action, target):
    acct = account(
        users=[user("u", policies=[doc(allow(action))]), user("victim")],
        roles=[role("r", ROOT_TRUST)],
        groups=[{"GroupName": "g", "GroupId": "G", "Arn": f"{A}:group/g"}],
    )
    assert find(build_edges(acct), "user/u", R.CAN_MODIFY_POLICY, target) is not None


def test_create_policy_version_targets_the_policy():
    policy = {"PolicyName": "P", "PolicyId": "P", "Arn": f"{A}:policy/P",
              "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True,
                                     "Document": doc(allow("s3:GetObject"))}]}
    acct = account(users=[user("u", policies=[doc(allow("iam:CreatePolicyVersion"))])],
                   policies=[policy])
    assert find(build_edges(acct), "user/u", R.CAN_MODIFY_POLICY, "policy/P") is not None


def test_modify_does_not_apply_to_wrong_kind():
    acct = account(users=[user("u", policies=[doc(allow("iam:PutRolePolicy"))]), user("v")])
    assert find(build_edges(acct), "user/u", R.CAN_MODIFY_POLICY, "user/v") is None


# ---- groups, warnings, robustness ------------------------------------------

def test_group_policy_flows_to_members():
    group = {"GroupName": "g", "GroupId": "G", "Arn": f"{A}:group/g",
             "GroupPolicyList": [{"PolicyName": "gp", "PolicyDocument": doc(allow("iam:PutUserPolicy"))}]}
    acct = account(users=[user("u", groups=["g"]), user("v")], groups=[group])
    assert find(build_edges(acct), "user/u", R.CAN_MODIFY_POLICY, "user/v") is not None


def test_missing_managed_policy_document_warns_and_skips_edge():
    raw = user("u")
    raw["AttachedManagedPolicies"] = [{"PolicyName": "Gone", "PolicyArn": f"{A}:policy/Gone"}]
    result = build_edges(account(users=[raw]))
    assert not [e for e in result.edges if e.relation_type == R.HAS_POLICY]
    assert any("Gone" in w for w in result.warnings)


def test_unknown_group_warns():
    result = build_edges(account(users=[user("u", groups=["nope"])]))
    assert any("nope" in w for w in result.warnings)


def test_malformed_policy_warns_instead_of_crashing():
    bad = {"Version": "2012-10-17", "Statement": [{"Effect": "Maybe", "Action": "*"}]}
    result = build_edges(account(users=[user("u", policies=[bad])]))
    assert any("unreadable policy" in w for w in result.warnings)


def test_empty_account():
    assert build_edges(parse_account({})).edges == ()


# ---- permission boundaries (flagged, not modelled) -------------------------

def with_boundary(raw):
    raw["PermissionsBoundary"] = {"PermissionsBoundaryType": "Policy",
                                  "PermissionsBoundaryArn": f"{A}:policy/Boundary"}
    return raw


def test_boundary_principal_assume_edge_is_flagged():
    acct = account(
        users=[with_boundary(user("u", policies=[doc(allow("sts:AssumeRole", f"{A}:role/r"))]))],
        roles=[role("r", ROOT_TRUST)])
    edge = find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r")
    assert edge.conditions == {"unevaluated_conditions": ["permissions_boundary"]}


def test_boundary_flag_merges_with_other_reasons():
    cond = allow("sts:AssumeRole", f"{A}:role/r", Condition={"Bool": {"x": "true"}})
    acct = account(users=[with_boundary(user("u", policies=[doc(cond)]))], roles=[role("r", ROOT_TRUST)])
    edge = find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r")
    assert edge.conditions == {"unevaluated_conditions": ["identity_policy", "permissions_boundary"]}


def test_boundary_flags_pass_role_and_modify_edges():
    acct = account(
        users=[with_boundary(user("u", policies=[doc(allow(["iam:PassRole", "lambda:CreateFunction", "iam:PutUserPolicy"]))])),
               user("v")],
        roles=[role("r", LAMBDA_TRUST)])
    result = build_edges(acct)
    for relation, target in ((R.CAN_PASS_ROLE, "role/r"), (R.CAN_MODIFY_POLICY, "user/v")):
        edge = find(result, "user/u", relation, target)
        assert "permissions_boundary" in edge.conditions["unevaluated_conditions"]


def test_principal_without_boundary_is_unaffected():
    acct = account(users=[user("u", policies=[doc(allow("sts:AssumeRole", f"{A}:role/r"))])],
                   roles=[role("r", ROOT_TRUST)])
    assert find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r").conditions == {}


def test_boundary_on_the_target_role_does_not_flag_the_caller():
    acct = account(users=[user("u", policies=[doc(allow("sts:AssumeRole", f"{A}:role/r"))])],
                   roles=[with_boundary(role("r", ROOT_TRUST))])
    assert find(build_edges(acct), "user/u", R.CAN_ASSUME, "role/r").conditions == {}
