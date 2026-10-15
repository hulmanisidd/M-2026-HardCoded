"""Typed view of `aws iam get-account-authorization-details` output.

This is the INPUT shape only (AWS's own PascalCase keys). It is owned by
ingestion and is not a shared contract. Everything downstream should use
the models in the root `contracts/` package instead.

Unknown keys are ignored on purpose: AWS adds fields over time and we only
care about the ones the attack-path graph needs.
"""
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Raw(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True, frozen=True)


class AttachedPolicyRef(_Raw):
    policy_name: str = Field(alias="PolicyName")
    policy_arn: str = Field(alias="PolicyArn")


class InlinePolicy(_Raw):
    policy_name: str = Field(alias="PolicyName")
    policy_document: dict[str, Any] = Field(alias="PolicyDocument")


class PermissionsBoundary(_Raw):
    boundary_type: str | None = Field(default=None, alias="PermissionsBoundaryType")
    boundary_arn: str = Field(alias="PermissionsBoundaryArn")


class Tag(_Raw):
    key: str = Field(alias="Key")
    value: str = Field(alias="Value")


class _Principal(_Raw):
    """Fields shared by users, groups and roles."""

    arn: str = Field(alias="Arn")
    path: str = Field(default="/", alias="Path")
    attached_policies: tuple[AttachedPolicyRef, ...] = Field(
        default=(), alias="AttachedManagedPolicies"
    )


class RawUser(_Principal):
    user_name: str = Field(alias="UserName")
    user_id: str = Field(alias="UserId")
    group_names: tuple[str, ...] = Field(default=(), alias="GroupList")
    inline_policies: tuple[InlinePolicy, ...] = Field(default=(), alias="UserPolicyList")
    permissions_boundary: PermissionsBoundary | None = Field(
        default=None, alias="PermissionsBoundary"
    )
    tags: tuple[Tag, ...] = Field(default=(), alias="Tags")


class RawGroup(_Principal):
    group_name: str = Field(alias="GroupName")
    group_id: str = Field(alias="GroupId")
    inline_policies: tuple[InlinePolicy, ...] = Field(default=(), alias="GroupPolicyList")


class RawRole(_Principal):
    role_name: str = Field(alias="RoleName")
    role_id: str = Field(alias="RoleId")
    trust_policy: dict[str, Any] = Field(alias="AssumeRolePolicyDocument")
    inline_policies: tuple[InlinePolicy, ...] = Field(default=(), alias="RolePolicyList")
    permissions_boundary: PermissionsBoundary | None = Field(
        default=None, alias="PermissionsBoundary"
    )
    tags: tuple[Tag, ...] = Field(default=(), alias="Tags")


class RawPolicyVersion(_Raw):
    version_id: str = Field(alias="VersionId")
    is_default: bool = Field(default=False, alias="IsDefaultVersion")
    document: dict[str, Any] = Field(alias="Document")


class RawManagedPolicy(_Raw):
    policy_name: str = Field(alias="PolicyName")
    policy_id: str = Field(alias="PolicyId")
    arn: str = Field(alias="Arn")
    versions: tuple[RawPolicyVersion, ...] = Field(default=(), alias="PolicyVersionList")

    def default_document(self) -> dict[str, Any] | None:
        """The version AWS actually enforces, or None if the dump lacks it."""
        for version in self.versions:
            if version.is_default:
                return version.document
        return None


_LIST_KEYS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")


class RawIamAccount(_Raw):
    users: tuple[RawUser, ...] = Field(default=(), alias="UserDetailList")
    groups: tuple[RawGroup, ...] = Field(default=(), alias="GroupDetailList")
    roles: tuple[RawRole, ...] = Field(default=(), alias="RoleDetailList")
    policies: tuple[RawManagedPolicy, ...] = Field(default=(), alias="Policies")
    # ARNs that appeared more than once in the dump. Filled in by the
    # validator below; the later copies are dropped.
    duplicate_arns: tuple[str, ...] = Field(default=(), alias="DuplicateArns")

    @model_validator(mode="before")
    @classmethod
    def _drop_duplicate_arns(cls, data):
        """Keep the first copy of anything listed twice.

        A real dump can repeat an item (for example when pages overlap while
        the account is changing). Two copies would give two entities with the
        same id, which GraphSnapshot rejects. Doing this once, here, keeps the
        entities and the edges built from them consistent.
        """
        if not isinstance(data, dict):
            return data
        data = dict(data)
        dropped: list[str] = []
        for key in _LIST_KEYS:
            seen: set[str] = set()
            kept = []
            for item in data.get(key) or []:
                arn = item.get("Arn") if isinstance(item, dict) else None
                if arn is not None and arn in seen:
                    dropped.append(arn)
                    continue
                if arn is not None:
                    seen.add(arn)
                kept.append(item)
            if key in data:
                data[key] = kept
        data["DuplicateArns"] = tuple(dropped)
        return data
