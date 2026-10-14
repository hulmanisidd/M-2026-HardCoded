"""Risk scoring contract for a single attack path."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, computed_field


class PathScore(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path_id: str = Field(min_length=1)
    likelihood: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=1.0)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk(self) -> float:
        return round(self.likelihood * self.impact, 6)