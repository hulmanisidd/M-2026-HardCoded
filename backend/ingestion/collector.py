"""Collect IAM data from a real AWS account (read-only) in the fixture shape.

The output of `collect_account` is the same dict the fixtures contain, so
`parse_account` / `build_snapshot` work on it unchanged.

SAFETY
  * This module makes exactly one kind of AWS call:
    iam:GetAccountAuthorizationDetails. It never writes anything.
  * Give it a read-only role/user holding only READ_ONLY_POLICY below.
  * A real dump contains your account's users, roles and policies. Treat it
    as sensitive: keep it out of git (or anonymize it first) and don't share it.
  * boto3 is imported lazily, so the rest of ingestion works without it.

Usage (from the repo root):
    python -m backend.ingestion.collector --profile my-readonly --out private/dump.json
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

LIST_KEYS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")
ALL_FILTERS = ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]

# The only permission the collector needs.
READ_ONLY_POLICY: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:GetAccountAuthorizationDetails",
            "Resource": "*",
        }
    ],
}


class CollectionError(RuntimeError):
    """Collection failed in a way the user can act on (credentials, permissions, boto3)."""


def _make_client(profile: str | None, region: str | None):
    try:
        import boto3
    except ImportError:
        raise CollectionError("boto3 is not installed. Run: pip install boto3") from None
    return boto3.Session(profile_name=profile, region_name=region).client("iam")


def _explain(error: Exception) -> CollectionError:
    """Turn common botocore errors into a message a person can act on."""
    name = type(error).__name__
    code = getattr(error, "response", {}).get("Error", {}).get("Code", "")
    if name == "NoCredentialsError":
        return CollectionError("No AWS credentials found. Use --profile or set AWS credentials.")
    if name == "ProfileNotFound":
        return CollectionError(f"AWS profile not found: {error}")
    if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
        return CollectionError(
            "Access denied. The credentials need iam:GetAccountAuthorizationDetails "
            "(see READ_ONLY_POLICY in backend/ingestion/collector.py)."
        )
    return CollectionError(f"AWS call failed ({code or name}): {error}")


def collect_account(
    client: Any | None = None,
    *,
    profile: str | None = None,
    region: str | None = None,
    include_aws_managed: bool = True,
) -> dict[str, Any]:
    """Fetch every user, group, role and managed policy in the account.

    include_aws_managed=False skips AWS's own managed policies (a much
    smaller response). Roles that attach one, like AdministratorAccess,
    will then show a "document not in the dump" warning later and their
    permissions will be unknown, so leave it on unless you have a reason.
    """
    if client is None:
        client = _make_client(profile, region)
    filters = [f for f in ALL_FILTERS if include_aws_managed or f != "AWSManagedPolicy"]
    merged: dict[str, list] = {key: [] for key in LIST_KEYS}
    try:
        paginator = client.get_paginator("get_account_authorization_details")
        for page in paginator.paginate(Filter=filters):
            for key in LIST_KEYS:
                merged[key].extend(page.get(key, []))
    except CollectionError:
        raise
    except Exception as error:  # botocore errors are not imported at module level
        raise _explain(error) from error
    return merged


def save_dump(data: dict[str, Any], path: str | Path) -> None:
    """Write a dump as JSON. AWS returns datetimes, so those become strings."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")


def detect_account_id(data: dict[str, Any]) -> str | None:
    """The account id found in the first user/role/group ARN, if any."""
    for key in ("UserDetailList", "RoleDetailList", "GroupDetailList"):
        for item in data.get(key, []):
            parts = item.get("Arn", "").split(":")
            if len(parts) > 4 and parts[4].isdigit():
                return parts[4]
    return None


def replace_account_id(data: dict[str, Any], old: str, new: str = "111122223333") -> dict[str, Any]:
    """Swap a 12-digit account id everywhere, so a dump can be shared as a fixture.

    This only changes the account id. Names, policy contents and tags stay
    as they were, so read the result before sharing it.
    """
    if not re.fullmatch(r"\d{12}", old) or not re.fullmatch(r"\d{12}", new):
        raise ValueError("account ids must be 12 digits")
    text = json.dumps(data, default=str)
    return json.loads(text.replace(old, new))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect IAM data (read-only) into a JSON dump.")
    parser.add_argument("--out", required=True, help="where to write the JSON dump")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", help="AWS region (IAM is global; rarely needed)")
    parser.add_argument("--no-aws-managed", action="store_true",
                        help="skip AWS-managed policies (smaller, but their permissions become unknown)")
    parser.add_argument("--anonymize", action="store_true",
                        help="replace the account id with 111122223333 before saving")
    args = parser.parse_args(argv)

    try:
        data = collect_account(
            profile=args.profile, region=args.region,
            include_aws_managed=not args.no_aws_managed,
        )
    except CollectionError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.anonymize:
        account_id = detect_account_id(data)
        if account_id:
            data = replace_account_id(data, account_id)
    save_dump(data, args.out)
    print(
        f"wrote {args.out}: {len(data['UserDetailList'])} users, "
        f"{len(data['GroupDetailList'])} groups, {len(data['RoleDetailList'])} roles, "
        f"{len(data['Policies'])} managed policies"
    )
    print("This file describes your account's permissions. Keep it out of git unless anonymized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
