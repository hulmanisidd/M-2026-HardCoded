"""Source freshness and system status: unknown/stale is never reported as safe."""
from datetime import datetime, timedelta, timezone

from backend.updates import OverallState, SourceEvidence, SourceState, StatusTracker, UpdateResult, UpdateStrategy

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def tracker(now):
    return StatusTracker(clock=lambda: now["t"], max_age=timedelta(hours=1))


def test_unseen_source_is_unknown_not_fresh():
    now = {"t": T0}
    t = tracker(now)
    assert t.source_status("aws").state == SourceState.UNKNOWN
    s = t.summary()
    assert s.overall == OverallState.UNKNOWN
    assert t.evidence_for(("aws",)) == SourceEvidence.SOURCE_UNAVAILABLE


def test_fresh_then_stale_with_time():
    now = {"t": T0}
    t = tracker(now)
    t.record_source_success("aws")
    assert t.source_status("aws").state == SourceState.FRESH
    assert t.evidence_for() == SourceEvidence.SOURCE_CONFIRMED
    now["t"] = T0 + timedelta(hours=2)
    assert t.source_status("aws").state == SourceState.STALE
    assert t.evidence_for() == SourceEvidence.SOURCE_STALE
    assert t.summary().overall == OverallState.DEGRADED


def test_failure_after_success_is_failed_until_next_success():
    now = {"t": T0}
    t = tracker(now)
    t.record_source_success("aws")
    now["t"] = T0 + timedelta(minutes=5)
    t.record_source_failure("aws", "throttled")
    st = t.source_status("aws")
    assert st.state == SourceState.FAILED and st.last_failure_reason == "throttled"
    assert t.evidence_for() == SourceEvidence.SOURCE_UNAVAILABLE
    now["t"] = T0 + timedelta(minutes=10)
    t.record_source_success("aws")
    assert t.source_status("aws").state == SourceState.FRESH


def test_partial_collection_is_never_fresh():
    now = {"t": T0}
    t = tracker(now)
    t.record_source_partial("aws", "pagination gave up")
    st = t.source_status("aws")
    assert st.state == SourceState.STALE and "partial" in st.note
    assert t.evidence_for() == SourceEvidence.SOURCE_STALE


def test_one_bad_source_degrades_overall_and_is_named():
    now = {"t": T0}
    t = StatusTracker(clock=lambda: now["t"], expected_sources=("aws", "analyzer"))
    t.record_source_success("aws")
    s = t.summary()                       # 'analyzer' was expected but never reported
    assert s.overall == OverallState.DEGRADED
    assert any("analyzer" in n and "unknown" in n for n in s.notes)
    t.record_source_success("analyzer")
    assert t.summary().overall == OverallState.OK


def test_summary_counts_updates_and_verifications():
    now = {"t": T0}
    t = tracker(now)
    t.record_source_success("aws")
    t.record_update(UpdateResult(applied=True, reason="graph_change_processed",
                                 graph_version="g_1", strategy=UpdateStrategy.FULL), path_count=3)
    t.record_update(UpdateResult(applied=False, reason="replayed_change", graph_version="g_1"))
    t.record_verification("VERIFIED")
    s = t.summary()
    assert s.graph_version == "g_1" and s.path_count == 3
    assert s.update_counts == {"graph_change_processed:full": 1, "replayed_change:none": 1}
    assert s.verification_counts == {"VERIFIED": 1}
    assert s.last_update_reason == "graph_change_processed"
