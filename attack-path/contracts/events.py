"""NormalizedEvent: a source-agnostic record of something that happened."""
from typing import Any

from pydantic import AwareDatetime, Field

from .base import ContractModel


class NormalizedEvent(ContractModel):
    event_id: str = Field(min_length=1)
    event_type: str = Field(min_length=1)  # e.g. "AttachRolePolicy"
    source: str = Field(min_length=1)  # e.g. "cloudtrail"
    occurred_at: AwareDatetime  # naive datetimes are rejected
    actor_id: str | None = None  # who did it (entity_id)
    target_id: str | None = None  # what it was done to (entity_id)
    payload: dict[str, Any] = Field(default_factory=dict)