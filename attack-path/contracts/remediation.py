"""Remediation contracts: which edges to cut, and what that achieves."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


class RemediationPlan(BaseModel):
    """A proposal to remove edges from a snapshot (feeds GraphSnapshot.fork)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    base_version: str = Field(min_length=1)
    removed_edge_ids: tuple[str, ...] = Field(min_length=1)
    rationale: str = ""

    @model_validator(mode="after")
    def _unique_edges(self) -> "RemediationPlan":
        if len(set(self.removed_edge_ids)) != len(self.removed_edge_ids):
            raise ValueError("removed_edge_ids contains duplicates")
        return self


class SimulationResult(BaseModel):
    """Outcome of applying a plan: paths before vs. after the fork."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: str = Field(min_length=1)
    before_version: str = Field(min_length=1)
    after_version: str = Field(min_length=1)
    paths_before: tuple[str, ...] = ()
    paths_after: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _versions_differ(self) -> "SimulationResult":
        if self.before_version == self.after_version:
            raise ValueError("a simulation must produce a new snapshot version")
        if not set(self.paths_after) <= set(self.paths_before):
            raise ValueError("removing edges cannot create new paths")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def blocked_path_ids(self) -> tuple[str, ...]:
        after = set(self.paths_after)
        return tuple(p for p in self.paths_before if p not in after)