"""Entity (brief 9.2). entity_id is the stable key; display_name is for humans only."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Entity(BaseModel):
    model_config = ConfigDict(frozen=True)

    entity_id: str
    entity_type: str
    display_name: str
    criticality: str
    attributes: dict = Field(default_factory=dict)