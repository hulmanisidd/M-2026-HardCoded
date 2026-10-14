"""Relationship: a directed edge in the attack-path graph."""
import hashlib
from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, Field, model_validator

from .base import ContractModel
from .vocab import RelationType


class EdgeStatus(StrEnum):
    """How much we trust that an edge currently exists.

    CONFIRMED   - directly observed in collected data and still fresh.
    INFERRED    - derived by reasoning (e.g. from a policy), not observed directly.
    STALE       - was observed, but the data is older than the freshness limit.
    UNKNOWN     - source data was incomplete or failed, so we can't say.
    INVALIDATED - known to no longer exist (removed or fixed).
    """

    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    STALE = "stale"
    UNKNOWN = "unknown"
    INVALIDATED = "invalidated"


def make_edge_id(
    source_id: str,
    relation_type: str,
    target_id: str,
    discriminator: str = "",
) -> str:
    """Derive a stable edge id.

    Rule: sha256 of source_id, relation_type, target_id and discriminator
    (joined with a separator character), first 16 hex chars, prefixed "e_".
    Status and timestamps are NOT part of the id, so an edge keeps its id
    when its status changes. Use `discriminator` to tell apart parallel
    edges between the same two nodes.
    """
    key = "\x1f".join([source_id, str(relation_type), target_id, discriminator])
    return "e_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class Relationship(ContractModel):
    edge_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    relation_type: RelationType
    status: EdgeStatus = EdgeStatus.UNKNOWN
    discriminator: str = ""
    valid_from: AwareDatetime | None = None
    valid_until: AwareDatetime | None = None
    conditions: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: tuple[str, ...] = ()
    observed_at: AwareDatetime | None = None

    @model_validator(mode="before")
    @classmethod
    def _fill_edge_id(cls, data: Any) -> Any:
        # If edge_id wasn't given, derive it from the other fields.
        if isinstance(data, dict) and not data.get("edge_id"):
            if all(k in data for k in ("source_id", "relation_type", "target_id")):
                data = {
                    **data,
                    "edge_id": make_edge_id(
                        data["source_id"],
                        data["relation_type"],
                        data["target_id"],
                        data.get("discriminator", ""),
                    ),
                }
        return data

    @model_validator(mode="after")
    def _check_window(self) -> "Relationship":
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self