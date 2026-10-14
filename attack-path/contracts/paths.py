"""Attack path contracts: an ordered, contiguous walk through a GraphSnapshot."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


class AttackStep(BaseModel):
    """One hop of an attack path, referencing an edge by ID."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    edge_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def _no_self_loop(self) -> "AttackStep":
        if self.source_id == self.target_id:
            raise ValueError("an attack step cannot loop back to its own source")
        return self


class AttackPath(BaseModel):
    """An ordered chain of steps, pinned to the snapshot version it was found in."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    snapshot_version: str = Field(min_length=1)
    steps: tuple[AttackStep, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_chain(self) -> "AttackPath":
        for prev, nxt in zip(self.steps, self.steps[1:]):
            if prev.target_id != nxt.source_id:
                raise ValueError(
                    f"path is not contiguous: {prev.edge_id} ends at "
                    f"{prev.target_id} but {nxt.edge_id} starts at {nxt.source_id}"
                )
        edge_ids = [s.edge_id for s in self.steps]
        if len(set(edge_ids)) != len(edge_ids):
            raise ValueError("path reuses an edge")
        nodes = [self.steps[0].source_id] + [s.target_id for s in self.steps]
        if len(set(nodes)) != len(nodes):
            raise ValueError("path revisits an entity")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def entry_id(self) -> str:
        return self.steps[0].source_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_id(self) -> str:
        return self.steps[-1].target_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def edge_ids(self) -> tuple[str, ...]:
        return tuple(s.edge_id for s in self.steps)