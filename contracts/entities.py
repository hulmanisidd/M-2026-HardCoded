"""Entity: a node in the attack-path graph."""
from typing import Any

from pydantic import Field

from .base import ContractModel
from .vocab import Criticality, NodeType


class Entity(ContractModel):
    entity_id: str = Field(min_length=1)  # stable unique id, e.g. an AWS ARN
    entity_type: NodeType
    name: str = Field(min_length=1)
    criticality: Criticality | None = None    
    account_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)