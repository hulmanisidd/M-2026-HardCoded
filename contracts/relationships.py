"""Relationship / edge (brief 9.3). Owner: P2."""
from __future__ import annotations

from enum import Enum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class EdgeStatus(str, Enum):
    CONFIRMED = "CONFIRMED"      # backed by collected evidence, within validity window
    INFERRED = "INFERRED"        # derived by the model, not directly observed
    STALE = "STALE"              # was confirmed, but is past its freshness window
    UNKNOWN = "UNKNOWN"          # evidence missing; never treat as safe OR as allowed
    INVALIDATED = "INVALIDATED"  # explicitly revoked or removed


class Relationship(BaseModel):
    model_config = ConfigDict(frozen=True)

    edge_id: str
    source_id: str
    relation_type: str
    target_id: str
    conditions: dict = Field(default_factory=dict)
    status: EdgeStatus
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: AwareDatetime | None = None
    valid_from: AwareDatetime | None = None
    valid_until: AwareDatetime | None = None