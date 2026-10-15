"""Role trust policies: "may this principal assume this role?"

Builds on policy.py. Same honesty rules: Conditions are not evaluated, they
only flag the answer as conditional.

How AWS treats a trust policy (same-account case):
  * Trust names the caller directly (its ARN, or "*")  -> the trust policy
    alone is enough. We call this DIRECT.
  * Trust names the account root (arn:aws:iam::<acct>:root)  -> trust is
    only half the answer; the caller's own identity policy must ALSO allow
    sts:AssumeRole on the role. We call this ACCOUNT_DELEGATED and leave the
    identity-policy check to the edge builder.
  * Cross-account callers and permission boundaries are not modelled yet.
"""
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from .policy import Effect, Statement, action_matches

ASSUME_ACTION = "sts:AssumeRole"


class TrustMatch(StrEnum):
    NONE = "none"
    ACCOUNT_DELEGATED = "account_delegated"  # needs the caller's identity policy too
    DIRECT = "direct"  # trust policy alone is enough


_RANK = {TrustMatch.NONE: 0, TrustMatch.ACCOUNT_DELEGATED: 1, TrustMatch.DIRECT: 2}


@dataclass(frozen=True)
class TrustResult:
    match: TrustMatch
    conditional: bool = False
    matched_sids: tuple[str, ...] = ()

    @property
    def trusted(self) -> bool:
        return self.match is not TrustMatch.NONE


def _aws_principals(statement: Statement) -> tuple[str, ...]:
    return statement.principals.get("AWS", ())


def _match_principal(statement: Statement, caller_arn: str, account_id: str) -> TrustMatch:
    """How does this one statement's Principal relate to the caller?"""
    root = f"arn:aws:iam::{account_id}:root"
    best = TrustMatch.NONE
    for principal in _aws_principals(statement):
        if principal == "*" or principal == caller_arn:
            return TrustMatch.DIRECT
        if principal == root or principal == account_id:
            best = TrustMatch.ACCOUNT_DELEGATED
    return best


def _not_principal_match(statement: Statement, caller_arn: str) -> bool:
    """NotPrincipal: everyone EXCEPT the listed ones."""
    listed = {p for values in statement.not_principals.values() for p in values}
    return caller_arn not in listed


def trust_allows_principal(
    statements: Iterable[Statement], caller_arn: str, account_id: str
) -> TrustResult:
    """Can `caller_arn` (an IAM user or role in `account_id`) assume the role?"""
    best = TrustMatch.NONE
    conditional = False
    sids: list[str] = []
    conditional_deny = False

    for statement in statements:
        if not action_matches(statement, ASSUME_ACTION):
            continue

        if statement.effect is Effect.DENY:
            if statement.not_principals:
                hit = _not_principal_match(statement, caller_arn)
            else:
                hit = _match_principal(statement, caller_arn, account_id) is not TrustMatch.NONE
            if hit:
                if not statement.has_conditions:
                    return TrustResult(TrustMatch.NONE, False, (statement.sid,) if statement.sid else ())
                conditional_deny = True
            continue

        if statement.not_principals:
            # Rare form. We approximate it as DIRECT but never as a sure thing.
            match = TrustMatch.DIRECT if _not_principal_match(statement, caller_arn) else TrustMatch.NONE
            stmt_conditional = True
        else:
            match = _match_principal(statement, caller_arn, account_id)
            stmt_conditional = statement.has_conditions

        if match is TrustMatch.NONE:
            continue
        if statement.sid:
            sids.append(statement.sid)
        # Prefer the strongest match; among equals prefer an unconditional one.
        if _RANK[match] > _RANK[best] or (
            _RANK[match] == _RANK[best] and conditional and not stmt_conditional
        ):
            best, conditional = match, stmt_conditional

    if best is TrustMatch.NONE:
        return TrustResult(TrustMatch.NONE)
    return TrustResult(best, conditional or conditional_deny, tuple(sids))


def trust_allows_service(statements: Iterable[Statement], service: str) -> TrustResult:
    """Can an AWS service (e.g. "lambda.amazonaws.com") assume the role?

    This is what makes a role usable by a service after iam:PassRole.
    """
    best_conditional: bool | None = None
    sids: list[str] = []
    for statement in statements:
        if not action_matches(statement, ASSUME_ACTION):
            continue
        services = statement.principals.get("Service", ())
        if not any(s == "*" or s.lower() == service.lower() for s in services):
            continue
        if statement.effect is Effect.DENY:
            if not statement.has_conditions:
                return TrustResult(TrustMatch.NONE)
            best_conditional = True if best_conditional is not None else best_conditional
            continue
        if statement.sid:
            sids.append(statement.sid)
        if best_conditional is None or (best_conditional and not statement.has_conditions):
            best_conditional = statement.has_conditions
    if best_conditional is None:
        return TrustResult(TrustMatch.NONE)
    return TrustResult(TrustMatch.DIRECT, best_conditional, tuple(sids))
