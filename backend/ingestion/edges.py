"""Raw IAM account -> contracts.Relationship edges.

Edge rules (the contract between ingestion and the path engine):

  MEMBER_OF          user -> group                      read straight from the data
  HAS_POLICY         principal -> policy entity         read straight from the data
  CAN_ASSUME         user/role -> role                  trust policy AND identity policy agree
  CAN_PASS_ROLE      user/role -> role                  iam:PassRole allowed, the role is trusted by
                                                        a service, and the principal may launch that
                                                        service (e.g. lambda:CreateFunction)
  CAN_MODIFY_POLICY  user/role -> user/group/role/policy  iam:Put*/Attach*/CreatePolicyVersion style
                                                        actions on the target

Status: MEMBER_OF and HAS_POLICY are CONFIRMED (observed). Everything derived
from reading policies defaults to INFERRED, matching the contract ("derived by
reasoning, not observed directly"). Change `policy_edge_status` if the team
decides otherwise.

Honesty rules (team rule 6): Conditions are never evaluated. An edge that
leans on one gets `conditions={"unevaluated_conditions": [...]}`, so the
graph treats it as conditional rather than certain.

Principals that carry a permissions boundary get
`unevaluated_conditions=["permissions_boundary"]` on every derived edge.

Known gaps (not modelled yet): permission boundaries (only flagged), SCPs, resource-based
policies, cross-account trust, invoking/triggering a launched service, and
non-IAM resource edges (S3, KMS, Secrets).
"""
from dataclasses import dataclass

from contracts.relationships import EdgeStatus, Relationship
from contracts.vocab import RelationType

from .normalizer import account_id_from_arn, inline_policy_id
from .policy import (
    Decision,
    Effect,
    PolicyParseError,
    Statement,
    action_matches,
    evaluate,
    parse_policy_document,
)
from .raw_models import RawIamAccount, RawUser
from .trust import TrustMatch, trust_allows_principal, trust_allows_service

PASS_ROLE = "iam:PassRole"
ASSUME_ROLE = "sts:AssumeRole"

# Which action lets a principal make a service use a passed role.
# Any one of the listed actions is enough.
SERVICE_LAUNCH_ACTIONS: dict[str, tuple[str, ...]] = {
    "lambda.amazonaws.com": ("lambda:CreateFunction",),
    "ec2.amazonaws.com": ("ec2:RunInstances",),
    "glue.amazonaws.com": ("glue:CreateJob", "glue:CreateDevEndpoint"),
    "cloudformation.amazonaws.com": ("cloudformation:CreateStack",),
    "ecs-tasks.amazonaws.com": ("ecs:RunTask",),
    "codebuild.amazonaws.com": ("codebuild:CreateProject",),
    "datapipeline.amazonaws.com": ("datapipeline:CreatePipeline",),
    "sagemaker.amazonaws.com": ("sagemaker:CreateNotebookInstance",),
}

# Actions that let a principal change who/what a target can do.
MODIFY_ACTIONS: dict[str, tuple[str, ...]] = {
    "user": ("iam:PutUserPolicy", "iam:AttachUserPolicy"),
    "group": ("iam:PutGroupPolicy", "iam:AttachGroupPolicy", "iam:AddUserToGroup"),
    "role": ("iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy"),
    "policy": ("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"),
}


@dataclass(frozen=True)
class EdgeBuildResult:
    edges: tuple[Relationship, ...]
    warnings: tuple[str, ...] = ()


@dataclass
class _Identity:
    """All identity-policy statements that apply to one principal."""

    statements: list[Statement]
    owner_of: dict[int, str]  # id(statement) -> policy entity id

    def evidence(self, result) -> tuple[str, ...]:
        found = {self.owner_of[id(s)] for s in result.matched_statements if id(s) in self.owner_of}
        return tuple(sorted(found))


class _Builder:
    def __init__(self, account: RawIamAccount, status: EdgeStatus):
        self.account = account
        self.status = status
        self.warnings: list[str] = []
        self.edges: dict[str, Relationship] = {}
        self.managed: dict[str, tuple[Statement, ...]] = {}
        self.groups = {g.group_name: g for g in account.groups}
        self.roles = {r.arn: r for r in account.roles}
        self.trust: dict[str, tuple[Statement, ...]] = {}

        for policy in account.policies:
            self.managed[policy.arn] = self._parse(policy.default_document(), policy.arn)
        for role in account.roles:
            self.trust[role.arn] = self._parse(role.trust_policy, f"{role.arn} (trust policy)")

    # -- helpers ----------------------------------------------------------

    def _parse(self, document, label: str) -> tuple[Statement, ...]:
        try:
            return parse_policy_document(document)
        except PolicyParseError as error:
            self.warnings.append(f"skipped unreadable policy {label}: {error}")
            return ()

    def _add(self, source, relation, target, status, conditions=None, evidence=()):
        edge = Relationship(
            source_id=source,
            target_id=target,
            relation_type=relation,
            status=status,
            conditions=conditions or {},
            evidence_ids=tuple(dict.fromkeys(evidence)),
        )
        self.edges.setdefault(edge.edge_id, edge)

    def _identity(self, principal) -> _Identity:
        statements: list[Statement] = []
        owner_of: dict[int, str] = {}

        def take(policy_id: str, parsed: tuple[Statement, ...]):
            for statement in parsed:
                statements.append(statement)
                owner_of[id(statement)] = policy_id

        def take_principal(p):
            for inline in p.inline_policies:
                pid = inline_policy_id(p.arn, inline.policy_name)
                take(pid, self._parse(inline.policy_document, pid))
            for ref in p.attached_policies:
                if ref.policy_arn in self.managed:
                    take(ref.policy_arn, self.managed[ref.policy_arn])

        take_principal(principal)
        if isinstance(principal, RawUser):
            for name in principal.group_names:
                if name in self.groups:
                    take_principal(self.groups[name])
        return _Identity(statements, owner_of)

    # -- structural edges -------------------------------------------------

    def structural(self):
        known_policies = set(self.managed)
        for user in self.account.users:
            for name in user.group_names:
                group = self.groups.get(name)
                if group is None:
                    self.warnings.append(f"{user.arn} is in unknown group {name!r}; MEMBER_OF skipped")
                    continue
                self._add(user.arn, RelationType.MEMBER_OF, group.arn, EdgeStatus.CONFIRMED)

        for principal in (*self.account.users, *self.account.groups, *self.account.roles):
            for inline in principal.inline_policies:
                self._add(principal.arn, RelationType.HAS_POLICY,
                          inline_policy_id(principal.arn, inline.policy_name), EdgeStatus.CONFIRMED)
            for ref in principal.attached_policies:
                if ref.policy_arn not in known_policies:
                    self.warnings.append(
                        f"{principal.arn} has {ref.policy_arn} attached but its document is "
                        "not in the dump; HAS_POLICY skipped and its permissions are unknown"
                    )
                    continue
                self._add(principal.arn, RelationType.HAS_POLICY, ref.policy_arn, EdgeStatus.CONFIRMED)

    # -- derived edges ----------------------------------------------------

    def derived(self):
        principals = [*self.account.users, *self.account.roles]
        for principal in principals:
            identity = self._identity(principal)
            self._assume_edges(principal, identity)
            self._pass_role_edges(principal, identity)
            self._modify_edges(principal, identity)

    def _assume_edges(self, principal, identity: _Identity):
        account_id = account_id_from_arn(principal.arn)
        for role in self.account.roles:
            if role.arn == principal.arn or account_id_from_arn(role.arn) != account_id:
                continue
            trust = trust_allows_principal(self.trust[role.arn], principal.arn, account_id)
            if not trust.trusted:
                continue
            ident = evaluate(identity.statements, ASSUME_ROLE, role.arn)
            if ident.decision is Decision.DENY:
                continue
            if trust.match is TrustMatch.ACCOUNT_DELEGATED and not ident.allowed:
                continue
            unevaluated = _boundary_flag(principal)
            if trust.conditional:
                unevaluated.append("trust_policy")
            if ident.allowed and ident.conditional:
                unevaluated.append("identity_policy")
            self._add(
                principal.arn, RelationType.CAN_ASSUME, role.arn, self.status,
                _conditions(unevaluated), (role.arn, *identity.evidence(ident)),
            )

    def _pass_role_edges(self, principal, identity: _Identity):
        account_id = account_id_from_arn(principal.arn)
        for role in self.account.roles:
            if account_id_from_arn(role.arn) != account_id:
                continue
            passed = evaluate(identity.statements, PASS_ROLE, role.arn)
            if not passed.allowed:
                continue
            for service, launch_actions in SERVICE_LAUNCH_ACTIONS.items():
                svc_trust = trust_allows_service(self.trust[role.arn], service)
                if not svc_trust.trusted:
                    continue
                launch = self._launch(identity, launch_actions)
                if launch is None:
                    continue
                unevaluated = _boundary_flag(principal)
                if passed.conditional or svc_trust.conditional or launch[1]:
                    unevaluated.append("pass_role_or_launch")
                conditions = _conditions(unevaluated)
                if launch[2]:
                    conditions["launch_action_resource_scope_unchecked"] = True
                self._add(
                    principal.arn, RelationType.CAN_PASS_ROLE, role.arn, self.status,
                    conditions, (role.arn, *identity.evidence(passed), *launch[3]),
                )
                break  # one edge per (principal, role) is enough

    @staticmethod
    def _launch(identity: _Identity, actions: tuple[str, ...]):
        """(allowed, conditional, resource_scoped, evidence) for the first usable action."""
        for action in actions:
            result = evaluate(identity.statements, action, "*")
            if result.allowed:
                return True, result.conditional, False, identity.evidence(result)
            # The Allow may be scoped to specific resources, which we can't
            # match without knowing the target. Keep it, but flag it.
            scoped = [s for s in identity.statements
                      if s.effect is Effect.ALLOW and action_matches(s, action)]
            if scoped:
                owners = {identity.owner_of[id(s)] for s in scoped}
                return True, True, True, tuple(sorted(owners))
        return None

    def _modify_edges(self, principal, identity: _Identity):
        account_id = account_id_from_arn(principal.arn)
        targets = (
            [("user", u.arn) for u in self.account.users]
            + [("group", g.arn) for g in self.account.groups]
            + [("role", r.arn) for r in self.account.roles]
            + [("policy", p.arn) for p in self.account.policies]
        )
        for kind, arn in targets:
            if account_id_from_arn(arn) != account_id:
                continue  # AWS-managed policies cannot be modified
            for action in MODIFY_ACTIONS[kind]:
                result = evaluate(identity.statements, action, arn)
                if result.allowed:
                    unevaluated = _boundary_flag(principal)
                    if result.conditional:
                        unevaluated.append("identity_policy")
                    self._add(
                        principal.arn, RelationType.CAN_MODIFY_POLICY, arn, self.status,
                        _conditions(unevaluated), identity.evidence(result),
                    )
                    break


def _boundary_flag(principal) -> list[str]:
    """Permission boundaries are not modelled, so a principal that has one may
    be allowed less than its policies say. Mark every edge it produces as
    conditional rather than let it look certain."""
    return ["permissions_boundary"] if principal.permissions_boundary else []


def _conditions(unevaluated: list[str]) -> dict:
    return {"unevaluated_conditions": sorted(set(unevaluated))} if unevaluated else {}


def build_edges(
    account: RawIamAccount, policy_edge_status: EdgeStatus = EdgeStatus.INFERRED
) -> EdgeBuildResult:
    """Derive every edge for the account, sorted by edge_id for determinism."""
    builder = _Builder(account, policy_edge_status)
    builder.structural()
    builder.derived()
    edges = tuple(sorted(builder.edges.values(), key=lambda e: e.edge_id))
    return EdgeBuildResult(edges=edges, warnings=tuple(builder.warnings))
