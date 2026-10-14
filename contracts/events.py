"""Normalized event (brief 9.1). Owner: P1. Timestamps must be timezone-aware."""
from __future__ import annotations

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    event_type: str
    event_time: AwareDatetime
    ingested_at: AwareDatetime
    source: str
    entity_ids: list[str]
    severity: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    # Never put raw secrets here: use references, hashes or redacted metadata.
    attributes: dict = Field(default_factory=dict)