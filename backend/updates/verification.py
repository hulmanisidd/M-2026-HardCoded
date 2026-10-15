"""P5 remediation verification.

P4 only ever emits SIMULATED recommendations. This module decides whether a
recommendation can be called SIMULATED, VERIFIED, PARTIALLY_VERIFIED, UNKNOWN
or FAILED, by re-running path discovery on the graph state *after* the fix.

Rule from the project brief: a successful change is not proof. VERIFIED needs
authoritative source evidence. Without it the best result is SIMULATED,
PARTIALLY_VERIFIED or UNKNOWN.

A path search that was truncated (path/depth cap) or that skipped unknown entry
or target IDs may have missed paths, so "no path found" is not proof. In that
case a result that would be VERIFIED is capped at PARTIALLY_VERIFIED.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from contracts.base import ContractModel
from contracts.graph import GraphSnapshot
from backend.paths.models import PathSearchResult
from contracts.paths import AttackPath, FeasibilityStatus
from contracts.remediation import (
    RemediationPlan,
    RemediationRecommendation,
    VerificationStatus,
)

# A search takes a snapshot and returns P3's full result (paths + stats), e.g.
# functools.partial(discover_paths, entry_points=..., targets=..., options=...)
PathSearch = Callable[[GraphSnapshot], PathSearchResult]


class SourceEvidence(StrEnum):
    """How the 'after' graph state was obtained."""

    SIMULATION = "simulation"              # forked copy, no real change
    SOURCE_CONFIRMED = "source_confirmed"  # authoritative state re-read, fresh
    SOURCE_STALE = "source_stale"          # re-read, but data is stale/partial
    SOURCE_UNAVAILABLE = "source_unavailable"  # could not be checked


class VerificationResult(ContractModel):
    recommendation_id: str
    plan_id: str
    status: str
    evidence: SourceEvidence
    before_version: str
    after_version: str
    blocked_path_ids: tuple[str, ...] = ()
    still_open_path_ids: tuple[str, ...] = ()   # expected blocked, still live
    new_path_ids: tuple[str, ...] = ()          # live after, not live before
    residual_path_ids: tuple[str, ...] = ()
    alternate_routes_remain: bool = False
    reasons: tuple[str, ...] = ()


def _live_ids(paths: list[AttackPath]) -> set[str]:
    return {
        p.path_id for p in paths
        if p.feasibility_status != FeasibilityStatus.BLOCKED
    }


def _active_plan_edges(after: GraphSnapshot, plan: RemediationPlan) -> list[str]:
    """Plan edges that still exist and are not invalidated in `after`."""
    wanted = set(plan.removed_edge_ids)
    return sorted(
        e.edge_id for e in after.edges
        if e.edge_id in wanted and str(e.status).lower() != "invalidated"
    )


class RemediationVerifier:
    """Registers recommendations and verifies them against an 'after' graph."""

    def __init__(self, search: PathSearch) -> None:
        self._search = search
        self._registry: dict[
            str, tuple[RemediationRecommendation, RemediationPlan, GraphSnapshot]
        ] = {}

    def register(
        self,
        recommendation: RemediationRecommendation,
        plan: RemediationPlan,
        before_snapshot: GraphSnapshot,
    ) -> None:
        # plan_id is added to the contract in the batched contracts PR; tolerate its absence.
        rec_plan_id = getattr(recommendation, "plan_id", None)
        if rec_plan_id is not None and rec_plan_id != plan.id:
            raise ValueError(
                f"recommendation points at plan {rec_plan_id}, "
                f"got plan {plan.id}"
            )
        self._registry[recommendation.recommendation_id] = (
            recommendation, plan, before_snapshot,
        )

    def get(
        self, recommendation_id: str
    ) -> tuple[RemediationRecommendation, RemediationPlan, GraphSnapshot]:
        """The registered (recommendation, plan, before_snapshot). KeyError if unknown."""
        return self._registry[recommendation_id]

    def verify_remediation(
        self,
        recommendation_id: str,
        *,
        after_snapshot: GraphSnapshot,
        evidence: SourceEvidence,
    ) -> VerificationResult:
        if recommendation_id not in self._registry:
            raise KeyError(f"unknown recommendation: {recommendation_id}")
        rec, plan, before = self._registry[recommendation_id]
        reasons: list[str] = []

        def result(status, **kw) -> VerificationResult:
            return VerificationResult(
                recommendation_id=rec.recommendation_id,
                plan_id=plan.id,
                status=status,
                evidence=evidence,
                before_version=before.version,
                after_version=after_snapshot.version,
                reasons=tuple(reasons),
                **kw,
            )

        # Guards: never verify against a different graph than P4 analysed.
        if rec.graph_version != before.version or plan.base_version != before.version:
            reasons.append("recommendation/plan were computed on a different graph version")
            return result(VerificationStatus.UNKNOWN)
        if after_snapshot.version == before.version:
            reasons.append("after-state has the same version as before-state; nothing changed")
            return result(VerificationStatus.UNKNOWN)
        if not rec.expected_blocked_path_ids:
            reasons.append("recommendation expected no blocked paths; nothing to verify")
            return result(VerificationStatus.UNKNOWN)

        before_result = self._search(before)
        after_result = self._search(after_snapshot)
        before_live = _live_ids(list(before_result.paths))
        after_live = _live_ids(list(after_result.paths))

        incomplete = []
        for label, res in (("before", before_result), ("after", after_result)):
            st = res.stats
            if st.truncated:
                incomplete.append(f"{label} search truncated ({st.truncation_reason})")
            if st.unknown_entry_ids or st.unknown_target_ids:
                incomplete.append(f"{label} search skipped unknown entry/target IDs")

        expected = set(rec.expected_blocked_path_ids)
        still_open = sorted(expected & after_live)
        new_paths = sorted(after_live - before_live)
        active_edges = _active_plan_edges(after_snapshot, plan)
        blocked = sorted(before_live - after_live)
        residual = sorted(after_live)
        facts = dict(
            blocked_path_ids=tuple(blocked),
            still_open_path_ids=tuple(still_open),
            new_path_ids=tuple(new_paths),
            residual_path_ids=tuple(residual),
            alternate_routes_remain=bool(residual),
        )

        if still_open:
            reasons.append(f"{len(still_open)} path(s) expected to be blocked are still live")
        if new_paths:
            reasons.append(f"fix created {len(new_paths)} new live path(s)")
        if active_edges:
            reasons.append(f"{len(active_edges)} planned edge(s) are still active")
        if still_open or new_paths or active_edges:
            return result(VerificationStatus.FAILED, **facts)

        if residual:
            reasons.append(f"{len(residual)} alternate route(s) remain after the fix")

        if incomplete:
            reasons.extend(incomplete)
            reasons.append("path search incomplete; absence of a path is not proof")

        if evidence == SourceEvidence.SIMULATION:
            reasons.append("simulation only; no authoritative source evidence")
            return result(VerificationStatus.SIMULATED, **facts)
        if evidence == SourceEvidence.SOURCE_CONFIRMED:
            if incomplete:
                return result(VerificationStatus.PARTIALLY_VERIFIED, **facts)
            reasons.append("authoritative source state confirms the paths are blocked")
            return result(VerificationStatus.VERIFIED, **facts)
        if evidence == SourceEvidence.SOURCE_STALE:
            reasons.append("source data is stale or partial; cannot fully verify")
            return result(VerificationStatus.PARTIALLY_VERIFIED, **facts)
        reasons.append("source could not be checked")
        return result(VerificationStatus.UNKNOWN, **facts)