"""IAM policy documents: parse statements and answer "does this allow X on Y?".

Scope (deliberately small, so we never claim more than we know):
  * Handles Effect, Action/NotAction, Resource/NotResource, Principal and
    Condition keys, plus the "string or list" and "dict or list" shortcuts
    AWS allows.
  * Wildcards `*` and `?` in actions and resources.
  * Explicit Deny beats Allow.
  * Conditions are NOT evaluated. A statement with a Condition is reported
    as conditional so later stages never treat it as a sure thing.
  * Policy variables like ${aws:username} are treated as `*`. That
    over-approximates what the policy allows (the safe side for an
    attack-path tool) but can add false positives.
  * Not modelled yet: permission boundaries, SCPs, session policies,
    resource-based policies. A result here means "the identity policies
    say so", not "AWS will allow it".
"""
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable

from functools import lru_cache

@lru_cache(maxsize=None)
def _wildcard_regex(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    pattern = _VARIABLE.sub("*", pattern)
    body = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(f"^{body}$", re.IGNORECASE if ignore_case else 0)
class PolicyParseError(ValueError):
    """The policy document is malformed. We fail loudly instead of guessing."""


class Effect(StrEnum):
    ALLOW = "Allow"
    DENY = "Deny"


@dataclass(frozen=True)
class Statement:
    effect: Effect
    sid: str | None = None
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    principals: dict[str, tuple[str, ...]] = field(default_factory=dict)
    not_principals: dict[str, tuple[str, ...]] = field(default_factory=dict)
    conditions: dict[str, Any] = field(default_factory=dict)

    @property
    def has_conditions(self) -> bool:
        return bool(self.conditions)


def _as_tuple(value: Any, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return tuple(value)
    raise PolicyParseError(f"{what} must be a string or list of strings, got {value!r}")


def _parse_principal(value: Any) -> dict[str, tuple[str, ...]]:
    if value is None:
        return {}
    if value == "*":
        return {"AWS": ("*",)}
    if isinstance(value, dict):
        return {key: _as_tuple(val, f"Principal.{key}") for key, val in value.items()}
    raise PolicyParseError(f"Principal must be '*' or an object, got {value!r}")


def parse_statement(raw: dict[str, Any]) -> Statement:
    if not isinstance(raw, dict):
        raise PolicyParseError(f"statement must be an object, got {raw!r}")
    try:
        effect = Effect(raw["Effect"])
    except KeyError:
        raise PolicyParseError("statement is missing Effect") from None
    except ValueError:
        raise PolicyParseError(f"bad Effect {raw['Effect']!r}") from None

    statement = Statement(
        effect=effect,
        sid=raw.get("Sid"),
        actions=_as_tuple(raw.get("Action"), "Action"),
        not_actions=_as_tuple(raw.get("NotAction"), "NotAction"),
        resources=_as_tuple(raw.get("Resource"), "Resource"),
        not_resources=_as_tuple(raw.get("NotResource"), "NotResource"),
        principals=_parse_principal(raw.get("Principal")),
        not_principals=_parse_principal(raw.get("NotPrincipal")),
        conditions=raw.get("Condition") or {},
    )
    if not statement.actions and not statement.not_actions:
        raise PolicyParseError("statement needs Action or NotAction")
    return statement


def parse_policy_document(document: dict[str, Any] | None) -> tuple[Statement, ...]:
    """Parse a policy document. A missing document gives no statements."""
    if not document:
        return ()
    if "Statement" not in document:
        raise PolicyParseError("policy document has no Statement")
    raw = document["Statement"]
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise PolicyParseError("Statement must be an object or a list")
    return tuple(parse_statement(item) for item in raw)


# --- matching -------------------------------------------------------------

_VARIABLE = re.compile(r"\$\{[^}]*\}")


def _wildcard_regex(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    pattern = _VARIABLE.sub("*", pattern)
    body = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(f"^{body}$", re.IGNORECASE if ignore_case else 0)


def wildcard_match(pattern: str, value: str, ignore_case: bool = False) -> bool:
    return bool(_wildcard_regex(pattern, ignore_case).match(value))


def _any_match(patterns: Iterable[str], value: str, ignore_case: bool) -> bool:
    return any(wildcard_match(p, value, ignore_case) for p in patterns)


def action_matches(statement: Statement, action: str) -> bool:
    """AWS action names are case-insensitive."""
    if statement.not_actions:
        return not _any_match(statement.not_actions, action, True)
    return _any_match(statement.actions, action, True)


def resource_matches(statement: Statement, resource: str) -> bool:
    """Resource ARNs are case-sensitive."""
    if statement.not_resources:
        return not _any_match(statement.not_resources, resource, False)
    if statement.resources:
        return _any_match(statement.resources, resource, False)
    return False


# --- evaluation -----------------------------------------------------------


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"  # explicit Deny matched
    IMPLICIT_DENY = "implicit_deny"  # nothing allowed it


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    # True when the answer leans on a Condition we did not evaluate
    # (a conditional Allow, or a conditional Deny that might still apply).
    conditional: bool = False
    matched_sids: tuple[str, ...] = ()
    matched_statements: tuple[Statement, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


def evaluate(
    statements: Iterable[Statement], action: str, resource: str
) -> PolicyResult:
    """Combine statements the way IAM does: explicit Deny > Allow > default deny."""
    allows: list[Statement] = []
    conditional_denies: list[Statement] = []

    for statement in statements:
        if not (action_matches(statement, action) and resource_matches(statement, resource)):
            continue
        if statement.effect is Effect.DENY:
            if not statement.has_conditions:
                return PolicyResult(Decision.DENY, False, _sids([statement]), (statement,))
            conditional_denies.append(statement)
        else:
            allows.append(statement)

    if not allows:
        return PolicyResult(Decision.IMPLICIT_DENY)

    has_sure_allow = any(not s.has_conditions for s in allows)
    matched = tuple(allows) + tuple(conditional_denies)
    return PolicyResult(
        Decision.ALLOW,
        conditional=(not has_sure_allow) or bool(conditional_denies),
        matched_sids=_sids(matched),
        matched_statements=matched,
    )


def _sids(statements: Iterable[Statement]) -> tuple[str, ...]:
    return tuple(s.sid for s in statements if s.sid)
