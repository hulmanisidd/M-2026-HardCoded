
"""Remediation recommendations, plans, and simulation results."""

from pydantic import (
    ConfigDict,
    Field,
    computed_field,
    model_validator,
)

from .base import ContractModel


class VerificationStatus(str):
    """Legacy verification status values."""
    PROPOSED = "PROPOSED"
    SIMULATED = "SIMULATED"
    APPROVED = "APPROVED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class RemediationRecommendation(ContractModel):
    recommendation_id: str
    graph_version: str
    action_type: str
    target_id: str
    estimated_cost: float | None = None
    expected_blocked_path_ids: list[str] = Field(default_factory=list)
    residual_path_ids: list[str] = Field(default_factory=list)
    estimated_risk_reduction: float | None = None
    assumptions: list[str] = Field(default_factory=list)
    verification_status: str = VerificationStatus.PROPOSED


class RemediationPlan(ContractModel):
    id: str = Field(min_length=1)
    base_version: str = Field(min_length=1)
    removed_edge_ids: tuple[str, ...] = Field(min_length=1)
    rationale: str = ""

    @model_validator(mode="after")
    def unique_edges(self) -> "RemediationPlan":
        if len(set(self.removed_edge_ids)) != len(self.removed_edge_ids):
            raise ValueError("removed_edge_ids contains duplicates")
        return self


class SimulationResult(ContractModel):
    plan_id: str = Field(min_length=1)
    before_version: str = Field(min_length=1)
    after_version: str = Field(min_length=1)
    paths_before: tuple[str, ...] = ()
    paths_after: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_simulation(self) -> "SimulationResult":
        if self.before_version == self.after_version:
            raise ValueError("a simulation must produce a new snapshot version")
        if not set(self.paths_after) <= set(self.paths_before):
            raise ValueError("removing edges cannot create new paths")
        return self

    @computed_field
    @property
    def blocked_path_ids(self) -> tuple[str, ...]:
        after = set(self.paths_after)
        return tuple(path for path in self.paths_before if path not in after)
