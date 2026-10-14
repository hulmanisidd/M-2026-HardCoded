"""Risk assessment (brief 9.5). Owner: P4.

Scales: likelihood_score, impact_score, risk_score in [0, 1].
likelihood_score / risk_score are None when required evidence is missing;
list what is missing in `unknowns`. Never fill in a normal-looking default.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RiskAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    path_id: str
    graph_version: str
    likelihood_score: float | None = Field(default=None, ge=0, le=1)
    impact_score: float = Field(ge=0, le=1)
    confidence: str
    risk_score: float | None = Field(default=None, ge=0, le=1)
    reasons: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)