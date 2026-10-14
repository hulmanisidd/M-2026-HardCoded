"""Raw IAM account -> contracts.Entity nodes.

Conventions (shared with the edge builder, so keep them stable):
  * entity_id is the AWS ARN.
  * Inline policies have no ARN, so they get a synthetic id:
        "<owner arn>#inline/<policy name>"
  * Policy documents are stored untouched in `attributes["document"]`
    so later stages (permission parsing, remediation) can read them.
  * AWS-managed policies (arn:aws:iam::aws:policy/...) have account_id None.
"""
from typing import Any

from contracts.entities import Entity
from contracts.vocab import NodeType

from .raw_models import InlinePolicy, RawIamAccount


def inline_policy_id(owner_arn: str, policy_name: str) -> str:
    return f"{owner_arn}#inline/{policy_name}"


def account_id_from_arn(arn: str) -> str | None:
    parts = arn.split(":")
    if len(parts) < 5 or not parts[4] or parts[4] == "aws":
        return None
    return parts[4]


def _tags(tags) -> dict[str, str]:
    return {tag.key: tag.value for tag in tags}


def _boundary(principal) -> str | None:
    boundary = principal.permissions_boundary
    return boundary.boundary_arn if boundary else None


def _inline_entities(owner_arn: str, policies: tuple[InlinePolicy, ...]) -> list[Entity]:
    return [
        Entity(
            entity_id=inline_policy_id(owner_arn, policy.policy_name),
            entity_type=NodeType.IAM_POLICY,
            name=policy.policy_name,
            account_id=account_id_from_arn(owner_arn),
            attributes={
                "document": policy.policy_document,
                "inline": True,
                "owner_arn": owner_arn,
            },
        )
        for policy in policies
    ]


def normalize_entities(account: RawIamAccount) -> tuple[Entity, ...]:
    """Build every node for the account, in a deterministic order."""
    entities: list[Entity] = []

    for user in account.users:
        attributes: dict[str, Any] = {
            "path": user.path,
            "tags": _tags(user.tags),
            "permissions_boundary": _boundary(user),
        }
        entities.append(Entity(
            entity_id=user.arn,
            entity_type=NodeType.IAM_USER,
            name=user.user_name,
            account_id=account_id_from_arn(user.arn),
            attributes=attributes,
        ))
        entities.extend(_inline_entities(user.arn, user.inline_policies))

    for group in account.groups:
        entities.append(Entity(
            entity_id=group.arn,
            entity_type=NodeType.IAM_GROUP,
            name=group.group_name,
            account_id=account_id_from_arn(group.arn),
            attributes={"path": group.path},
        ))
        entities.extend(_inline_entities(group.arn, group.inline_policies))

    for role in account.roles:
        entities.append(Entity(
            entity_id=role.arn,
            entity_type=NodeType.IAM_ROLE,
            name=role.role_name,
            account_id=account_id_from_arn(role.arn),
            attributes={
                "path": role.path,
                "tags": _tags(role.tags),
                "permissions_boundary": _boundary(role),
                "trust_policy": role.trust_policy,
            },
        ))
        entities.extend(_inline_entities(role.arn, role.inline_policies))

    for policy in account.policies:
        entities.append(Entity(
            entity_id=policy.arn,
            entity_type=NodeType.IAM_POLICY,
            name=policy.policy_name,
            account_id=account_id_from_arn(policy.arn),
            attributes={
                "document": policy.default_document(),
                "inline": False,
            },
        ))

    return tuple(entities)
