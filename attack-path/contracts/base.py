"""Shared base class for every contract model."""
from pydantic import BaseModel, ConfigDict


class ContractModel(BaseModel):
    """Base for all contracts.

    frozen=True   -> instances are immutable, so nobody mutates a shared object.
    extra="forbid" -> unknown fields raise an error, so typos don't pass silently.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")