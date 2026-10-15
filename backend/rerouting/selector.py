"""Primary identification and backup ranking. Deterministic."""
from __future__ import annotations

from collections.abc import Iterable

from .models import AccessPath, CandidateAssessment, Verdict
from .validators import (
    ValidationContext, assess_candidate, check_graph_connected, check_permission_granted, check_policy_constraints,
)


def pick_primary(paths: Iterable[AccessPath], ctx: ValidationContext) -> AccessPath | None:
    """Primary when the caller has no usage data (ASSUMPTION, conservative).

    Only routes verified TODAY (graph, permission, policy) can be primary; unverified routes
    are never promoted. Which verified route is really in use is unknowable here, so if the
    change breaks or exposes one of them, THAT route is assumed to be the one in use (it
    might recommend a backup that was not strictly needed, never the opposite). If the change
    affects none, the shortest verified route is returned. Ties break by path_id.
    Pass AccessRequirement.primary_edge_ids when the real route is known.
    """
    today = sorted(
        (p for p in paths
         if all(fn(p, ctx).verdict is Verdict.VERIFIED
                for fn in (check_graph_connected, check_permission_granted, check_policy_constraints))),
        key=lambda p: (p.hops, p.path_id),
    )
    if not today:
        return None
    affected = [p for p in today if assess_candidate(p, ctx).verdict is not Verdict.VERIFIED]
    return (affected or today)[0]


def rank_backups(assessed: Iterable[CandidateAssessment]) -> list[AccessPath]:
    """Only fully VERIFIED candidates, fewest hops first (fewer hops = fewer things to break)."""
    verified = [a.path for a in assessed if a.verdict is Verdict.VERIFIED]
    return sorted(verified, key=lambda p: (p.hops, p.path_id))
