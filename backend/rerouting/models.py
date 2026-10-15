"""Contracts for legitimate-access rerouting.

Rules baked into the types:
  * UNKNOWN is a first-class verdict and is never treated as safe.
  * A path is usable only if EVERY required check is VERIFIED.
  * VERIFIED without evidence is impossible to construct.
  * A report can never claim "deployed": the mode is a Literal.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, computed_field, model_validator

from contracts.base import ContractModel
from contracts.paths import AttackPath, FeasibilityStatus


class Verdict(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNKNOWN = "unknown"          # missing/weak evidence: NOT safe


class CheckName(StrEnum):
    GRAPH_CONNECTED = "graph_connected"
    PERMISSION_GRANTED = "permission_granted"
    POLICY_CONSTRAINTS = "policy_constraints"
    AVAILABILITY = "availability"
    NO_ATTACK_PATH_REINTRODUCED = "no_attack_path_reintroduced"
    LEGITIMATE_ACCESS_PRESERVED = "legitimate_access_preserved"


REQUIRED_CHECKS: frozenset[CheckName] = frozenset(CheckName)


class Outcome(StrEnum):
    PRIMARY_STILL_VALID = "primary_still_valid"
    BACKUP_RECOMMENDED = "backup_recommended"
    NO_VALID_BACKUP = "no_valid_backup"
    PRIMARY_UNVERIFIABLE = "primary_unverifiable"


class Evidence(ContractModel):
    source: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    reference: str | None = None


class AccessRequirement(ContractModel):
    """What a legitimate principal must keep being able to do."""

    principal_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    max_hops: int = Field(default=4, ge=1)
    primary_edge_ids: tuple[str, ...] | None = None
    trusted_entry_ids: tuple[str, ...] = ()
    unavailable_edge_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> AccessRequirement:
        if self.principal_id == self.resource_id:
            raise ValueError("principal and resource must differ")
        if self.primary_edge_ids is not None and not self.primary_edge_ids:
            raise ValueError("primary_edge_ids must be None or non-empty")
        return self

    @property
    def trusted_entries(self) -> frozenset[str]:
        return frozenset((self.principal_id, *self.trusted_entry_ids))


class AccessPath(ContractModel):
    """A LEGITIMATE access route (deliberately not an AttackPath type)."""

    path_id: str = Field(min_length=1)
    graph_version: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    node_ids: tuple[str, ...] = Field(min_length=2)
    edge_ids: tuple[str, ...] = Field(min_length=1)
    discovered_feasibility: FeasibilityStatus | None = None

    @model_validator(mode="after")
    def _shape(self) -> AccessPath:
        if len(self.node_ids) != len(self.edge_ids) + 1:
            raise ValueError("node_ids must have exactly one more item than edge_ids")
        if self.node_ids[0] != self.principal_id or self.node_ids[-1] != self.resource_id:
            raise ValueError("path must run principal -> resource")
        if len(set(self.node_ids)) != len(self.node_ids):
            raise ValueError("path revisits a node")
        if len(set(self.edge_ids)) != len(self.edge_ids):
            raise ValueError("path reuses an edge")
        return self

    @property
    def hops(self) -> int:
        return len(self.edge_ids)

    @classmethod
    def from_p3(cls, p: AttackPath) -> AccessPath:
        return cls(
            path_id=p.path_id, graph_version=p.graph_version,
            principal_id=p.entry_node_id, resource_id=p.target_node_id,
            node_ids=p.node_ids, edge_ids=p.edge_ids,
            discovered_feasibility=p.feasibility_status,
        )


class CheckResult(ContractModel):
    check: CheckName
    verdict: Verdict = Verdict.UNKNOWN
    reason: str = "no evidence"
    evidence: tuple[Evidence, ...] = ()

    @model_validator(mode="after")
    def _verified_needs_evidence(self) -> CheckResult:
        if self.verdict is Verdict.VERIFIED and not self.evidence:
            raise ValueError(f"{self.check.value}: VERIFIED requires evidence")
        return self


class CandidateAssessment(ContractModel):
    path: AccessPath
    checks: dict[CheckName, CheckResult] = Field(default_factory=dict)

    def verdict_for(self, name: CheckName) -> Verdict:
        res = self.checks.get(name)
        return res.verdict if res else Verdict.UNKNOWN

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict(self) -> Verdict:
        vs = [self.verdict_for(c) for c in REQUIRED_CHECKS]
        if any(v is Verdict.REJECTED for v in vs):
            return Verdict.REJECTED
        if all(v is Verdict.VERIFIED for v in vs):
            return Verdict.VERIFIED
        return Verdict.UNKNOWN

    @property
    def blockers(self) -> tuple[str, ...]:
        out = []
        for c in sorted(REQUIRED_CHECKS, key=lambda x: x.value):
            v = self.verdict_for(c)
            if v is not Verdict.VERIFIED:
                why = self.checks[c].reason if c in self.checks else "check not run"
                out.append(f"{c.value}: {v.value} ({why})")
        return tuple(out)


class SwitchSimulation(ContractModel):
    """Simulated 'remediation applied, traffic moves to the backup'."""

    backup_path_id: str
    plan_id: str
    access_preserved: bool
    residual_before: tuple[str, ...]
    residual_after: tuple[str, ...]
    unknown_before: tuple[str, ...] = ()
    unknown_after: tuple[str, ...] = ()
    known_risk_before: float
    known_risk_after: float
    exposed_attack_path_ids: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    @property
    def new_attack_path_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.residual_after) - set(self.residual_before)))

    @property
    def new_unknown_path_ids(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.unknown_after) - set(self.unknown_before)))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_safe(self) -> bool:
        return (
            self.access_preserved
            and not self.new_attack_path_ids
            and not self.new_unknown_path_ids
            and not self.exposed_attack_path_ids
            and self.known_risk_after <= self.known_risk_before + 1e-9
        )


class ReroutingReport(ContractModel):
    requirement: AccessRequirement
    graph_version: str
    outcome: Outcome
    mode: Literal["simulated_recommendation_only"] = "simulated_recommendation_only"
    primary: AccessPath | None = None
    selected_backup: AccessPath | None = None
    assessments: tuple[CandidateAssessment, ...] = ()
    simulation: SwitchSimulation | None = None
    search_truncated: bool = False
    notes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _honest(self) -> ReroutingReport:
        if self.outcome is Outcome.BACKUP_RECOMMENDED:
            if self.selected_backup is None or self.simulation is None:
                raise ValueError("a recommended backup needs a path and a simulation")
            if not self.simulation.is_safe:
                raise ValueError("an unsafe simulation cannot back a recommendation")
        elif self.selected_backup is not None:
            raise ValueError(f"{self.outcome.value} must not carry a backup path")
        return self

    @property
    def protected_edge_ids(self) -> tuple[str, ...]:
        return self.selected_backup.edge_ids if self.selected_backup else ()
