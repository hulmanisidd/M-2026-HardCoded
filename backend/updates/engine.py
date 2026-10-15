"""UpdateEngine: the one public P5 object.

Wires P2 (graph repository), P3 (path discovery via the coordinator), P4 (risk
ranking, injected) and the verifier together, and implements the P5 contract:

    handle_change(change) -> UpdateResult
    verify_remediation(recommendation_id) -> VerificationReport
    reconcile() -> ReconciliationResult

Everything outside P5 is injected, so it runs against mocks.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from backend.graph.models import GraphChange
from backend.graph.repository import GraphRepository
from backend.paths.models import GraphReader
from contracts import (
    AttackPath,
    FeasibilityStatus,
    GraphSnapshot,
    NormalizedEvent,
    PathOptions,
    RiskAssessment,
)
from contracts.base import ContractModel
from contracts.remediation import (
    RemediationPlan,
    RemediationRecommendation,
    VerificationStatus,
)

from .coordinator import UpdateCoordinator
from .events import EventApplier, EventIntake, EventOutcome, NotifyingGraphRepository
from .models import UpdateResult, UpdateStrategy
from .reconciliation import (
    InventoryProvider,
    ReconciliationResult,
    Reconciler,
    ReconciliationStatus,
)
from .scheduler import ReconciliationScheduler
from .status import StatusTracker, SystemStatus
from .verification import RemediationVerifier, SourceEvidence, VerificationResult

# P4: rank_paths(paths, snapshot) -> list[RiskAssessment]
RiskRanker = Callable[[list[AttackPath], GraphSnapshot], list[RiskAssessment]]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class VerificationReport(ContractModel):
    """A verification verdict plus the refreshed context around it."""

    result: VerificationResult
    recommendation: RemediationRecommendation          # status/residuals updated
    residual_assessments: tuple[RiskAssessment, ...] = ()
    reconciliation: ReconciliationResult | None = None


class UpdateEngine:
    def __init__(
        self,
        *,
        repo: GraphRepository,
        entry_points: Iterable[str],
        targets: Iterable[str],
        options: PathOptions | None = None,
        risk_ranker: RiskRanker | None = None,
        inventory_provider: InventoryProvider | None = None,
        event_applier: EventApplier | None = None,
        status: StatusTracker | None = None,
        source_name: str = "inventory",
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._repo = repo
        self._ranker = risk_ranker
        self._status = status or StatusTracker(clock=clock)
        self._lock = threading.RLock()
        self._assessments: dict[str, RiskAssessment] = {}
        self._assessed_version: str | None = None
        self._recomputes = 0

        self._coordinator = UpdateCoordinator(
            repo.snapshot,
            entry_points,
            targets,
            options=options,
            status=self._status,
            on_update=self._after_update,
        )
        self._verifier = RemediationVerifier(self._coordinator_search)
        self._intake = EventIntake(self._coordinator, event_applier, status=self._status)
        self._reconciler = Reconciler(
            repo, self._coordinator, inventory_provider,
            status=self._status, source_name=source_name,
        )
        self._registry: dict[str, tuple[RemediationRecommendation, RemediationPlan]] = {}
        self._watched = NotifyingGraphRepository(repo, self._on_graph_change)

    # ---- wiring helpers ---------------------------------------------
    def _coordinator_search(self, snapshot: GraphSnapshot):
        return self._coordinator.search(snapshot)

    def _on_graph_change(self, change: GraphChange) -> None:
        self.handle_change(change)

    @property
    def coordinator(self) -> UpdateCoordinator:
        return self._coordinator

    @property
    def watched_repo(self) -> GraphRepository:
        """Write through this and every P2 change is forwarded to P5 automatically."""
        return self._watched

    @property
    def status_tracker(self) -> StatusTracker:
        return self._status

    @property
    def risk_recompute_count(self) -> int:
        return self._recomputes

    # ---- lifecycle ----------------------------------------------------
    def start(self) -> UpdateResult:
        """Initial discovery (and initial risk assessment if a ranker is set)."""
        return self._coordinator.initialize()

    def make_scheduler(self, interval) -> ReconciliationScheduler:
        return ReconciliationScheduler(self.reconcile, interval, clock=self._status.now)

    # ---- inbound changes ----------------------------------------------
    def handle_change(self, change: GraphChange) -> UpdateResult:
        return self._coordinator.handle_change(change)

    def handle_event(self, event: NormalizedEvent) -> EventOutcome:
        return self._intake.handle_event(event)

    # ---- risk (P4) ------------------------------------------------------
    @property
    def assessments(self) -> tuple[RiskAssessment, ...]:
        with self._lock:
            return tuple(self._assessments[k] for k in sorted(self._assessments))

    @property
    def assessed_version(self) -> str | None:
        return self._assessed_version

    def _after_update(self, result: UpdateResult, graph: GraphReader) -> None:
        """Coordinator hook: keep risk results tied to the graph version."""
        if self._ranker is None:
            return
        with self._lock:
            # Never let an older result overwrite a newer one.
            if result.graph_version != self._coordinator.last_version:
                return
            if result.strategy == UpdateStrategy.SKIPPED:
                # Proven unrelated to every path: same assessments, new version.
                self._assessments = {
                    k: a.model_copy(update={"graph_version": result.graph_version})
                    for k, a in self._assessments.items()
                }
                self._assessed_version = result.graph_version
                return
        paths = [
            p for p in self._coordinator.dependency_index.all_paths()
            if p.feasibility_status != FeasibilityStatus.BLOCKED
        ]
        snapshot = self._repo.snapshot()
        if snapshot.version != result.graph_version:
            return  # graph moved on; the newer update will recompute
        ranked = self._ranker(paths, snapshot)
        with self._lock:
            if result.graph_version != self._coordinator.last_version:
                return
            self._assessments = {a.path_id: a for a in ranked}
            self._assessed_version = result.graph_version
            self._recomputes += 1

    # ---- reconciliation ------------------------------------------------
    def reconcile(self) -> ReconciliationResult:
        return self._reconciler.reconcile()

    # ---- remediation verification ---------------------------------------
    def register_recommendation(
        self,
        recommendation: RemediationRecommendation,
        plan: RemediationPlan,
        before_snapshot: GraphSnapshot | None = None,
    ) -> None:
        """Remember a P4 recommendation. `before_snapshot` defaults to the
        current graph, which must be the version P4 analysed."""
        before = before_snapshot or self._repo.snapshot()
        self._verifier.register(recommendation, plan, before)
        self._registry[recommendation.recommendation_id] = (recommendation, plan)

    def verify_remediation(self, recommendation_id: str) -> VerificationReport:
        """Verify a recommendation against refreshed authoritative state.

        With an inventory provider: refresh the source, reconcile the graph
        through P2, recompute paths, then judge. The provider's freshness and
        completeness decide the evidence level. Without one (or if it fails)
        the best possible answer is SIMULATED / UNKNOWN - never VERIFIED.
        """
        if recommendation_id not in self._registry:
            raise KeyError(f"unknown recommendation: {recommendation_id}")
        rec, plan = self._registry[recommendation_id]
        _, _, before = self._verifier.get(recommendation_id)

        recon: ReconciliationResult | None = None
        if not self._reconciler.has_provider:
            after = before.fork(plan.removed_edge_ids)
            evidence = SourceEvidence.SIMULATION
        else:
            recon = self._reconciler.reconcile()
            after = self._repo.snapshot()
            evidence = recon.evidence

        result = self._verifier.verify_remediation(
            recommendation_id, after_snapshot=after, evidence=evidence
        )

        # Source confirms nothing changed and the planned edge(s) are still
        # live: that is a failed fix, not an unknown one.
        if (
            result.status == VerificationStatus.UNKNOWN
            and evidence == SourceEvidence.SOURCE_CONFIRMED
            and after.version == before.version
            and recon is not None
            and recon.status == ReconciliationStatus.IN_SYNC
            and self._plan_edges_live(after, plan)
        ):
            result = result.model_copy(update={
                "status": VerificationStatus.FAILED,
                "reasons": result.reasons + (
                    "authoritative source still shows the planned edge(s) active; "
                    "the fix was not applied",
                ),
            })

        residual: tuple[RiskAssessment, ...] = ()
        if self._ranker is not None and result.residual_path_ids:
            keep = set(result.residual_path_ids)
            live = [p for p in self._coordinator_search(after).paths if p.path_id in keep]
            residual = tuple(self._ranker(live, after))

        self._status.record_verification(str(result.status))
        updated = rec.model_copy(update={
            "verification_status": str(result.status),
            "residual_path_ids": list(result.residual_path_ids),
        })
        return VerificationReport(
            result=result, recommendation=updated,
            residual_assessments=residual, reconciliation=recon,
        )

    @staticmethod
    def _plan_edges_live(snapshot: GraphSnapshot, plan: RemediationPlan) -> bool:
        return any(
            (e := snapshot.get_edge(x)) is not None and str(e.status).lower() != "invalidated"
            for x in plan.removed_edge_ids
        )

    # ---- status ----------------------------------------------------------
    def system_status(self) -> SystemStatus:
        return self._status.summary()
