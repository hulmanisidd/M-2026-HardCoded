"""Scheduler ticks, P1 event intake, and P2 change forwarding."""
from datetime import datetime, timedelta, timezone

from backend.updates import (
    EdgeInvalidationApplier, EventIntake, NotifyingGraphRepository, ReconciliationScheduler,
    ReconciliationStatus, Reconciler, SourceInventory, StatusTracker, UpdateCoordinator,
)
from contracts import NormalizedEvent
from p5_helpers import chain_repo, edge, entity, index_matches_fresh, source_from

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


def ev(event_id, edge_id, event_type="iam.edge.invalidated", source="cloudtrail"):
    return NormalizedEvent(event_id=event_id, event_type=event_type, source=source,
                           occurred_at=T0, ingested_at=T0, attributes={"edge_id": edge_id})


# ---- scheduler -------------------------------------------------------------
def test_scheduler_runs_only_when_due():
    now = {"t": T0}
    calls = []
    sch = ReconciliationScheduler(lambda: calls.append(1) or "r", timedelta(minutes=10),
                                  clock=lambda: now["t"])
    assert sch.tick() == "r" and len(calls) == 1
    now["t"] = T0 + timedelta(minutes=9)
    assert sch.tick() is None and len(calls) == 1
    now["t"] = T0 + timedelta(minutes=10)
    assert sch.tick() == "r" and len(calls) == 2


def test_scheduler_survives_a_failing_run_and_retries_next_interval():
    now = {"t": T0}
    state = {"fail": True}

    def run():
        if state["fail"]:
            raise RuntimeError("source down")
        return "ok"

    sch = ReconciliationScheduler(run, timedelta(minutes=1), clock=lambda: now["t"])
    assert sch.tick() is None and "source down" in sch.last_error
    assert sch.tick() is None and sch.runs == 1           # no hot retry loop
    state["fail"] = False
    now["t"] = T0 + timedelta(minutes=1)
    assert sch.tick() == "ok" and sch.last_error is None


def test_periodic_reconciliation_detects_a_missed_update():
    repo, edges = chain_repo("a", "b", "c")
    status = StatusTracker()
    coord = UpdateCoordinator(repo.snapshot, ["a"], ["c"], status=status)
    coord.initialize()
    rec = Reconciler(repo, coord,
                     lambda: SourceInventory(source_from(repo), datetime.now(timezone.utc)),
                     status=status)
    now = {"t": T0}
    sch = ReconciliationScheduler(rec.reconcile, timedelta(minutes=5), clock=lambda: now["t"])

    assert sch.tick().status == ReconciliationStatus.IN_SYNC
    repo.invalidate_edge(edges[0].edge_id)               # change nobody told P5 about
    assert sch.tick() is None                            # not due yet - still stale
    now["t"] = T0 + timedelta(minutes=5)
    res = sch.tick()
    assert res.missed_update_detected is True
    assert len(coord.dependency_index) == 0


# ---- P1 event intake ---------------------------------------------------------
def test_event_is_applied_through_p2_and_triggers_recompute():
    repo, edges = chain_repo("a", "b", "c")
    status = StatusTracker(clock=lambda: T0)
    coord = UpdateCoordinator(repo.snapshot, ["a"], ["c"], status=status)
    coord.initialize()
    intake = EventIntake(coord, EdgeInvalidationApplier(repo), status=status)

    out = intake.handle_event(ev("e1", edges[0].edge_id))
    assert out.accepted and out.reason == "applied"
    assert out.updates[0].dropped_path_ids
    assert len(coord.dependency_index) == 0
    assert status.source_status("cloudtrail").state.value == "fresh"


def test_duplicate_event_is_not_applied_twice():
    repo, edges = chain_repo("a", "b", "c")
    coord = UpdateCoordinator(repo.snapshot, ["a"], ["c"])
    coord.initialize()
    intake = EventIntake(coord, EdgeInvalidationApplier(repo))
    assert intake.handle_event(ev("e1", edges[0].edge_id)).accepted
    dup = intake.handle_event(ev("e1", edges[0].edge_id))
    assert dup.accepted is False and dup.reason == "duplicate_event"
    # Same fact under a NEW event id: P2 replay is a no-op, nothing recomputed.
    again = intake.handle_event(ev("e2", edges[0].edge_id))
    assert again.reason == "no_graph_change"
    assert again.updates[0].reason == "replayed_change"


def test_unrelated_event_type_changes_nothing():
    repo, edges = chain_repo("a", "b", "c")
    coord = UpdateCoordinator(repo.snapshot, ["a"], ["c"])
    coord.initialize()
    intake = EventIntake(coord, EdgeInvalidationApplier(repo))
    out = intake.handle_event(ev("e1", edges[0].edge_id, event_type="login.suspicious"))
    assert out.reason == "no_graph_change" and out.updates == ()
    assert len(coord.dependency_index) == 1


def test_failed_apply_is_recorded_and_can_be_retried():
    repo, edges = chain_repo("a", "b", "c")
    status = StatusTracker()
    coord = UpdateCoordinator(repo.snapshot, ["a"], ["c"], status=status)
    coord.initialize()
    intake = EventIntake(coord, EdgeInvalidationApplier(repo), status=status)
    bad = intake.handle_event(ev("e1", "e_does_not_exist"))
    assert bad.accepted is False and bad.reason == "apply_failed" and "KeyError" in bad.error
    assert status.source_status("cloudtrail").state.value == "failed"
    # The same event id may be retried (it was never applied).
    good = intake.handle_event(ev("e1", edges[0].edge_id))
    assert good.accepted


def test_no_applier_is_reported_not_swallowed():
    repo, edges = chain_repo("a", "b", "c")
    coord = UpdateCoordinator(repo.snapshot, ["a"], ["c"])
    out = EventIntake(coord, None).handle_event(ev("e1", edges[0].edge_id))
    assert out.accepted is False and out.reason == "no_event_applier"


# ---- P2 subscription -------------------------------------------------------
def test_notifying_repository_forwards_every_write_to_the_coordinator():
    repo, _ = chain_repo("a", "b", "c")
    coord = UpdateCoordinator(repo.snapshot, ["a"], ["c"])
    coord.initialize()
    watched = NotifyingGraphRepository(repo, coord.handle_change)

    watched.upsert_edge(edge("a", "c"))
    assert len(coord.dependency_index) == 2
    watched.upsert_entity(entity("lonely"))
    assert index_matches_fresh(coord, repo, ["a"], ["c"])

def test_failed_event_is_not_accepted_when_applier_raises():
    repo, edges = chain_repo("a", "b", "c")
    status = StatusTracker()
    coord = UpdateCoordinator(repo.snapshot, ["a"], ["c"], status=status)
    coord.initialize()

    calls = {"count": 0}

    def failing_applier(event):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("simulated graph update failure")
        return [repo.invalidate_edge(edges[0].edge_id)]

    intake = EventIntake(coord, failing_applier, status=status)
    event = ev("e-failure", edges[0].edge_id)

    failed = intake.handle_event(event)

    assert failed.accepted is False
    assert failed.reason == "apply_failed"
    assert "simulated graph update failure" in failed.error
    assert status.source_status("cloudtrail").state.value == "failed"

    # The same event ID must be retryable after failure.
    retried = intake.handle_event(event)

    assert retried.accepted is True
    assert retried.reason == "applied"
    assert calls["count"] == 2

def test_failed_event_after_graph_write_does_not_report_success():
    repo, edges = chain_repo("a", "b", "c")
    coord = UpdateCoordinator(repo.snapshot, ["a"], ["c"])
    coord.initialize()

    def partially_failing_applier(event):
        repo.invalidate_edge(edges[0].edge_id)
        raise RuntimeError("failure after graph write")

    intake = EventIntake(coord, partially_failing_applier)
    before = repo.get_edge(edges[0].edge_id)

    out = intake.handle_event(ev("e-partial", edges[0].edge_id))

    assert out.accepted is False
    assert out.reason == "apply_failed"
    assert repo.get_edge(edges[0].edge_id) != before
