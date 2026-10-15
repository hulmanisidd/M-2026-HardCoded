from __future__ import annotations

from dataclasses import dataclass

from backend.paths.models import DEFAULT_ATTACK_RELATIONS
from contracts.vocab import RelationType

# Relations a legitimate route may use: P3's attack-step set plus group
# membership, minus privilege escalation. ASSUMPTION: needs team review.
DEFAULT_LEGIT_RELATIONS: frozenset[str] = frozenset(
    {str(r) for r in DEFAULT_ATTACK_RELATIONS} | {str(RelationType.MEMBER_OF)}
) - {str(RelationType.CAN_MODIFY_POLICY)}


@dataclass(frozen=True)
class ReroutingPolicy:
    legit_relations: frozenset[str] = DEFAULT_LEGIT_RELATIONS
    require_evidence: bool = True      # fail-closed
    max_candidates: int = 200
