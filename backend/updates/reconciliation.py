"""Full reconciliation: compare the authoritative inventory with the graph.

Detects missed updates (the graph moved without the coordinator hearing about
it, or the source changed without the graph hearing about it), repairs drift
only through P2's repository interface, and recomputes paths afterwards.

Honesty rules:
* A source we could not read gives UNKNOWN, never "in sync".
* A partial inventory cannot prove an edge is gone, so absent edges are
  reported but not invalidated, and the result is UNKNOWN, never "in sync".
* Nothing is deleted: edges missing from the source are INVALIDATED (kept for
  history). P2 has no entity removal, so extra entities are reported only.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from backend.graph.models import GraphChange
from backend.graph.repository import GraphRepository
from contracts.base import ContractModel
from contracts.graph import GraphSnapshot
from contracts.relationships import EdgeStatus

from .coordinator import UpdateCoordinator
from .models import UpdateResult
from .status import StatusTracker
from .verification import SourceEvidence


class DriftKind(StrEnum):
    VERSION_DRIFT = "version_drift"
    ENTITY_MISSING_IN_GRAPH = "entity_missing_in_graph"
    ENTITY_NOT_IN_SOURCE = "entity_not_in_source"
    ENTITY_CHANGED = "entity_changed"
    EDGE_MISSING_IN_GRAPH = "edge_missing_in_graph"
    EDGE_NOT_IN_SOURCE = "edge_not_in_source"
    EDGE_CHANGED = "edge_changed"


class ReconciliationStatus(StrEnum):
    IN_SYNC = "in_sync"
    DRIFT_REPAIRED = "drift_repaired"
    DRIFT_DETECTED = "drift_detected"  # some drift could not be repaired
    UNKNOWN = "unknown"                # source unreadable or partial


class DriftItem(ContractModel):
    kind: DriftKind
    subject_id: str
    detail: str = ""
    repaired: bool = False


class ReconciliationResult(ContractModel):
    status: ReconciliationStatus
    evidence: SourceEvidence
    drift: tuple[DriftItem, ...] = ()
    missed_update_detected: bool = False
    graph_version_before: str
    graph_version_after: str
    resync: UpdateResult | None = None
    reasons: tuple[str, ...] = ()

    @property
    def unresolved_count(self) -> int:
        return sum(1 for d in self.drift if not d.repaired)


@dataclass(frozen=True)
class SourceInventory:
    """Authoritative state as collected (and normalized) by P1."""

    snapshot: GraphSnapshot
    collected_at: datetime
    complete: bool = True   # False = partial collection / pagination gave up
    source: str = "inventory"


InventoryProvider = Callable[[], SourceInventory]


def _dump(model) -> dict:
    data = model.model_dump(mode="json")
    data.pop("observed_at", None)  # re-observed every collection; not drift
    return data


def diff_inventory(source: GraphSnapshot, graph: GraphSnapshot, *, complete: bool):
    """Pure comparison. Returns a list of (DriftItem, source_obj | None)."""
    out = []
    src_e = {e.entity_id: e for e in source.entities}
    gr_e = {e.entity_id: e for e in graph.entities}
    for eid in sorted(src_e.keys() - gr_e.keys()):
        out.append((DriftItem(kind=DriftKind.ENTITY_MISSING_IN_GRAPH, subject_id=eid), src_e[eid]))
    for eid in sorted(src_e.keys() & gr_e.keys()):
        if _dump(src_e[eid]) != _dump(gr_e[eid]):
            out.append((DriftItem(kind=DriftKind.ENTITY_CHANGED, subject_id=eid), src_e[eid]))
    for eid in sorted(gr_e.keys() - src_e.keys()):
        out.append((DriftItem(
            kind=DriftKind.ENTITY_NOT_IN_SOURCE, subject_id=eid,
            detail="graph has an entity the source does not; the graph interface cannot remove entities"
            if complete else "absent from a partial inventory; not proof it is gone",
        ), None))

    src_x = {e.edge_id: e for e in source.edges}
    gr_x = {e.edge_id: e for e in graph.edges}
    for xid in sorted(src_x.keys() - gr_x.keys()):
        if src_x[xid].status != EdgeStatus.INVALIDATED:
            out.append((DriftItem(kind=DriftKind.EDGE_MISSING_IN_GRAPH, subject_id=xid), src_x[xid]))
    for xid in sorted(src_x.keys() & gr_x.keys()):
        if _dump(src_x[xid]) != _dump(gr_x[xid]):
            out.append((DriftItem(kind=DriftKind.EDGE_CHANGED, subject_id=xid), src_x[xid]))
    for xid in sorted(gr_x.keys() - src_x.keys()):
        if gr_x[xid].status != EdgeStatus.INVALIDATED:  # invalidated == already gone
            out.append((DriftItem(
                kind=DriftKind.EDGE_NOT_IN_SOURCE, subject_id=xid,
                detail="" if complete else "absent from a partial inventory; not proof it is gone",
            ), None))
    return out


class Reconciler:
    def __init__(
        self,
        repo: GraphRepository,
        coordinator: UpdateCoordinator,
        inventory_provider: InventoryProvider | None,
        *,
        status: StatusTracker | None = None,
        source_name: str = "inventory",
        apply: bool = True,
    ) -> None:
        self._repo = repo
        self._coordinator = coordinator
        self._provider = inventory_provider
        self._status = status
        self._source_name = source_name
        self._apply = apply

    @property
    def has_provider(self) -> bool:
        return self._provider is not None

    def reconcile(self) -> ReconciliationResult:
        before = self._repo.snapshot()
        last = self._coordinator.last_version
        version_drift = last is not None and before.version != last
        reasons: list[str] = []
        drift: list[DriftItem] = []
        if version_drift:
            drift.append(DriftItem(
                kind=DriftKind.VERSION_DRIFT, subject_id=before.version,
                detail=f"coordinator last processed {last}; graph is at {before.version} "
                       "(missed notification, or an edge validity window was crossed)",
                repaired=False,
            ))
            reasons.append("graph moved without the coordinator being told")

        # --- 1. read the authoritative source ------------------------
        if self._provider is None:
            return self._finish(
                before, drift, reasons + ["no inventory provider configured"],
                SourceEvidence.SOURCE_UNAVAILABLE, version_drift, unknown=True,
            )
        try:
            inv = self._provider()
        except Exception as exc:  # collection failure must surface, not hide
            reason = f"{type(exc).__name__}: {exc}"
            if self._status:
                self._status.record_source_failure(self._source_name, reason)
            return self._finish(
                before, drift, reasons + [f"source could not be read ({reason})"],
                SourceEvidence.SOURCE_UNAVAILABLE, version_drift, unknown=True,
            )

        source_name = inv.source or self._source_name
        evidence = SourceEvidence.SOURCE_CONFIRMED
        if not inv.complete:
            evidence = SourceEvidence.SOURCE_STALE
            reasons.append("inventory is partial; absence of a fact is not proof")
            if self._status:
                self._status.record_source_partial(source_name, "partial inventory", at=inv.collected_at)
        else:
            if self._status:
                self._status.record_source_success(source_name, at=inv.collected_at)
            if self._status and (
                self._status.now() - inv.collected_at > self._status.max_age_for(source_name)
            ):
                evidence = SourceEvidence.SOURCE_STALE
                reasons.append("inventory is older than the freshness limit")

        # --- 2. compare and repair through P2 ------------------------
        found = diff_inventory(inv.snapshot, before, complete=inv.complete)
        for item, src_obj in found:
            repaired = False
            detail = item.detail
            if self._apply and src_obj is not None:
                repaired, detail = self._repair(item, src_obj, detail)
            elif self._apply and item.kind == DriftKind.EDGE_NOT_IN_SOURCE and inv.complete:
                repaired, detail = self._invalidate(item.subject_id, detail)
            drift.append(item.model_copy(update={"repaired": repaired, "detail": detail}))

        return self._finish(
            before, drift, reasons, evidence, version_drift,
            unknown=not inv.complete,
        )

    # ---- repairs: only ever through the P2 repository interface -------
    def _repair(self, item: DriftItem, src_obj, detail: str) -> tuple[bool, str]:
        try:
            if item.kind in (DriftKind.ENTITY_MISSING_IN_GRAPH, DriftKind.ENTITY_CHANGED):
                self._repo.upsert_entity(src_obj)
            else:  # edge missing / changed: a fresh authoritative observation
                self._repo.upsert_edge(src_obj, reinstate=True)
            return True, detail
        except (ValueError, KeyError) as exc:
            return False, f"repair failed: {exc}"

    def _invalidate(self, edge_id: str, detail: str) -> tuple[bool, str]:
        try:
            self._repo.invalidate_edge(edge_id)
            return True, detail
        except KeyError as exc:
            return False, f"repair failed: {exc}"

    def _finish(
        self, before: GraphSnapshot, drift: list[DriftItem], reasons: list[str],
        evidence: SourceEvidence, version_drift: bool, *, unknown: bool,
    ) -> ReconciliationResult:
        repaired_any = any(d.repaired for d in drift)
        resync = None
        if repaired_any or version_drift or self._coordinator.last_version is None:
            resync = self._coordinator.resync("reconciliation")
            # The coordinator has now caught up with the graph.
            drift = [
                d.model_copy(update={"repaired": True}) if d.kind == DriftKind.VERSION_DRIFT else d
                for d in drift
            ]
        after = self._repo.snapshot()

        unresolved = [d for d in drift if not d.repaired]
        if unknown:
            status = ReconciliationStatus.UNKNOWN
        elif unresolved:
            status = ReconciliationStatus.DRIFT_DETECTED
        elif drift:
            status = ReconciliationStatus.DRIFT_REPAIRED
        else:
            status = ReconciliationStatus.IN_SYNC

        if self._status:
            self._status.record_reconciliation(status.value, len(unresolved))
        return ReconciliationResult(
            status=status,
            evidence=evidence,
            drift=tuple(drift),
            missed_update_detected=version_drift,
            graph_version_before=before.version,
            graph_version_after=after.version,
            resync=resync,
            reasons=tuple(reasons),
        )
