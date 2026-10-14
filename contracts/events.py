from typing import Any

from pydantic import AwareDatetime, Field, model_validator

from .base import ContractModel


class NormalizedEvent(ContractModel):
    event_id: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    source: str = Field(min_length=1)

    # Event timing
    occurred_at: AwareDatetime
    ingested_at: AwareDatetime | None = None

    # Related entities
    actor_id: str | None = None
    target_id: str | None = None
    entity_ids: tuple[str, ...] = ()

    # Evidence and event details
    severity: str | None = None
    evidence_ids: tuple[str, ...] = ()
    payload: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_entity_references(self) -> "NormalizedEvent":
        if not self.entity_ids:
            # Derive references when actor/target are supplied.
            ids = tuple(
                dict.fromkeys(
                    value for value in (self.actor_id, self.target_id)
                    if value is not None
                )
            )
            if ids:
                object.__setattr__(self, "entity_ids", ids)
        return self