"""Remediation recommendation (brief 9.6). Owner: P4 (P5 updates verification_status)."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class VerificationStatus(str, Enum):
    PROPOSED = "PROPOSED"
    SIMULATED = "SIMULATED"
    APPROVED = "APPROVED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class RemediationRecommendation(BaseModel):
    model_config = ConfigDict(frozen=True)

    recommendation_id: str
    graph_version: str
    action_type: str
    target_id: str
    estimated_cost: float | None = None
    expected_blocked_path_ids: list[str] = Field(default_factory=list)
    residual_path_ids: list[str] = Field(default_factory=list)
    estimated_risk_reduction: float | None = None
    assumptions: list[str] = Field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.PROPOSED