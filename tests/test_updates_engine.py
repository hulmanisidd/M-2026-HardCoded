"""End-to-end P5 engine with the REAL P2 repository, P3 discovery and P4 ranking/remediation."""
from datetime import datetime, timedelta, timezone

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.seed_data import ENTRY_KEYS, TARGET_KEYS, load_into
from backend.remediation.candidates import generate_candidates
from backend.remediation.scoring import rank_paths
from backend.remediation.simulation import recommend
from backend.updates import (
    OverallState, SourceEvidence, SourceInventory, StatusTracker, UpdateEngine, UpdateStrategy,
)
from contracts.remediation import VerificationStatus
from p5_helpers import edge, entity, source_from


def now():
    return datetime.now(timezone.utc)


def build(provider=None, **kw):
    repo = InMemoryGraphRepository()
    seed = load_into(repo)
    entries = [seed.entity_ids[k] for k in ENTRY_KEYS]
    targets = [seed.entity_ids[k] for k in TARGET_KEYS]
    engine = UpdateEngine(repo=repo, entry_points=entries, targets=targets,
                          risk_ranker=rank_paths, inventory_provider=provider, **kw)
    engine.start()
    return repo, engine, entries, targets


def recommendation(repo, engine):
    """Ask real P4 for a fix on the current graph and register it with P5."""
    snap = repo.snapshot()
    finder = lambda s: list(engine.coordinator.search(s).paths)
    cand = generate_candidates(finder(snap), snap)[0]
    rec = recommend(cand, snap, finder)
    engine.register_recommendation(rec, cand.plan, snap)
    return rec, cand, snap


# ---- risk recomputation tied to graph versions -------------------------------
def test_start_assesses_paths_on_the_current_version():
    repo, engine, *_ = build()
    assert engine.assessments
    assert {a.graph_version for a in engine.assessments} == {repo.snapshot().version}
    assert engine.assessed_version == repo.snapshot().version


def test_changed_permission_invalidates_paths_and_recomputes_risk():
    repo, engine, *_ = build()
    watched = engine.watched_repo                         # P2 writes flow into P5
    before_ids = {a.path_id for a in engine.assessments}
    recomputes = engine.risk_recompute_count
    used = sorted({e for p in engine.coordinator.dependency_index.all_paths() for e in p.edge_ids})[0]

    watched.invalidate_edge(used)

    after_ids = {a.path_id for a in engine.assessments}
    assert after_ids < before_ids                          # affected paths gone, alternates stay
    assert engine.risk_recompute_count == recomputes + 1
    assert {a.graph_version for a in engine.assessments} == {repo.snapshot().version}


def test_unrelated_change_does_not_recompute_risk_but_retags_it():
    repo, engine, *_ = build()
    watched = engine.watched_repo
    recomputes = engine.risk_recompute_count
    before = {a.path_id: a.risk_score for a in engine.assessments}

    watched.upsert_entity(entity("isolated"))

    assert engine.risk_recompute_count == recomputes
    assert {a.path_id: a.risk_score for a in engine.assessments} == before
    assert {a.graph_version for a in engine.assessments} == {repo.snapshot().version}


# ---- verification --------------------------------------------------------------
def test_without_a_source_the_best_answer_is_simulated():
    repo, engine, *_ = build()
    rec, *_ = recommendation(repo, engine)
    report = engine.verify_remediation(rec.recommendation_id)
    assert report.result.evidence == SourceEvidence.SIMULATION
    assert report.result.status == VerificationStatus.SIMULATED
    assert report.recommendation.verification_status == VerificationStatus.SIMULATED


def test_fresh_complete_source_confirming_the_fix_is_verified_with_alternates():
    holder = {}
    repo, engine, *_ = build(lambda: SourceInventory(holder["src"], now()))
    rec, cand, snap = recommendation(repo, engine)
    holder["src"] = snap.fork(cand.plan.removed_edge_ids)   # source: planned edge(s) are gone

    report = engine.verify_remediation(rec.recommendation_id)

    assert report.result.status == VerificationStatus.VERIFIED
    assert report.result.evidence == SourceEvidence.SOURCE_CONFIRMED
    assert report.result.alternate_routes_remain is True    # seed has other routes
    assert report.residual_assessments                      # P4 re-scored what is left
    assert {a.path_id for a in report.residual_assessments} == set(report.result.residual_path_ids)
    assert report.recommendation.verification_status == VerificationStatus.VERIFIED
    # The engine's own picture refreshed through P2 -> P3 as well.
    assert all(e not in {x for p in engine.coordinator.dependency_index.all_paths() for x in p.edge_ids}
               for e in cand.plan.removed_edge_ids)
    assert engine.system_status().verification_counts == {"VERIFIED": 1}


def test_fix_not_actually_applied_in_source_is_failed_not_unknown():
    holder = {}
    repo, engine, *_ = build(lambda: SourceInventory(holder["src"], now()))
    rec, cand, snap = recommendation(repo, engine)
    holder["src"] = source_from(repo)                        # source unchanged: edge still there
    report = engine.verify_remediation(rec.recommendation_id)
    assert report.result.status == VerificationStatus.FAILED
    assert any("not applied" in r for r in report.result.reasons)


def test_stale_source_cannot_fully_verify():
    holder = {}
    repo, engine, *_ = build(lambda: SourceInventory(holder["src"], now() - timedelta(days=3)))
    rec, cand, snap = recommendation(repo, engine)
    holder["src"] = snap.fork(cand.plan.removed_edge_ids)
    report = engine.verify_remediation(rec.recommendation_id)
    assert report.result.status == VerificationStatus.PARTIALLY_VERIFIED
    assert report.result.evidence == SourceEvidence.SOURCE_STALE


def test_partial_source_cannot_fully_verify_and_graph_keeps_the_edge():
    holder = {}
    repo, engine, *_ = build(lambda: SourceInventory(holder["src"], now(), complete=False))
    rec, cand, snap = recommendation(repo, engine)
    holder["src"] = snap.fork(cand.plan.removed_edge_ids)
    report = engine.verify_remediation(rec.recommendation_id)
    assert report.result.status != VerificationStatus.VERIFIED
    # A partial read cannot prove the edge is gone, so the graph still has it live.
    assert repo.get_edge(cand.plan.removed_edge_ids[0]).status.value != "invalidated"


def test_unreachable_source_is_unknown_never_verified():
    def down():
        raise ConnectionError("aws unreachable")

    repo, engine, *_ = build(down)
    rec, *_ = recommendation(repo, engine)
    report = engine.verify_remediation(rec.recommendation_id)
    assert report.result.status == VerificationStatus.UNKNOWN
    assert report.result.evidence == SourceEvidence.SOURCE_UNAVAILABLE
    assert engine.system_status().overall != OverallState.OK


def test_recommendation_computed_on_an_older_graph_version_is_unknown():
    repo, engine, *_ = build()
    snap = repo.snapshot()
    finder = lambda s: list(engine.coordinator.search(s).paths)
    cand = generate_candidates(finder(snap), snap)[0]
    rec = recommend(cand, snap, finder)                     # P4 analysed version V0
    engine.watched_repo.upsert_entity(entity("something-new"))   # graph moves on to V1
    engine.register_recommendation(rec, cand.plan)          # registered against V1
    report = engine.verify_remediation(rec.recommendation_id)
    assert report.result.status == VerificationStatus.UNKNOWN
    assert any("different graph version" in r for r in report.result.reasons)


def test_unknown_recommendation_raises():
    _, engine, *_ = build()
    try:
        engine.verify_remediation("nope")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


# ---- reconciliation + status through the engine --------------------------------
def test_engine_reconcile_catches_a_missed_update_and_updates_status():
    box = {}
    repo, engine, *_ = build(lambda: SourceInventory(source_from(box["repo"]), now()))
    box["repo"] = repo
    used = sorted({e for p in engine.coordinator.dependency_index.all_paths() for e in p.edge_ids})[0]
    repo.invalidate_edge(used)                                  # bypasses the watched repo
    res = engine.reconcile()
    assert res.missed_update_detected is True
    assert engine.system_status().last_reconciliation_status == "drift_repaired"
    assert engine.make_scheduler(timedelta(minutes=5)).tick() is not None
