"""Integration check for P2 (graph) + P3 (paths) + P5 (coordinator, verifier).

Needs no P4 code. Uses the shared seed organization.
"""

from functools import partial

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.seed_data import (
    ENTRY_KEYS,
    EXPECTED_NON_BLOCKED_COUNT,
    TARGET_KEYS,
    load_into,
)
from backend.paths import discover_paths
from backend.updates.coordinator import UpdateCoordinator
from backend.updates.verification import RemediationVerifier, SourceEvidence
from contracts import PathOptions
from contracts.paths import FeasibilityStatus
from contracts.remediation import (
    RemediationPlan,
    RemediationRecommendation,
    VerificationStatus,
)


def _setup():
    repo = InMemoryGraphRepository()
    seed = load_into(repo)
    entries = [seed.entity_ids[k] for k in ENTRY_KEYS]
    targets = [seed.entity_ids[k] for k in TARGET_KEYS]
    coordinator = UpdateCoordinator(
        graph_reader_factory=repo.snapshot, entry_points=entries, targets=targets
    )
    return repo, entries, targets, coordinator


def _live(paths):
    return {p.path_id for p in paths if p.feasibility_status != FeasibilityStatus.BLOCKED}


def _edge_that_blocks_some_but_not_all(repo, entries, targets):
    snap = repo.snapshot()
    search = partial(discover_paths, entry_points=entries, targets=targets)
    before = search(snap).paths
    live_before = _live(before)
    for edge_id in dict.fromkeys(e for p in before for e in p.edge_ids):
        after = _live(search(snap.fork((edge_id,))).paths)
        if live_before - after and after:
            return edge_id
    raise AssertionError("no suitable edge in the seed")


def test_p2_p3_seed_matches_ground_truth():
    repo, entries, targets, _ = _setup()
    paths = discover_paths(repo.snapshot(), entries, targets, PathOptions()).paths
    assert len(_live(paths)) == EXPECTED_NON_BLOCKED_COUNT


def test_p5_initial_index_matches_p3():
    repo, entries, targets, coordinator = _setup()
    coordinator.initialize()
    fresh = discover_paths(repo.snapshot(), entries, targets, PathOptions()).paths
    assert {p.path_id for p in coordinator.dependency_index.all_paths()} == {
        p.path_id for p in fresh
    }


def test_p5_tracks_a_real_p2_change_and_keeps_alternates():
    repo, entries, targets, coordinator = _setup()
    coordinator.initialize()
    before = {p.path_id for p in coordinator.dependency_index.all_paths()}

    edge_id = _edge_that_blocks_some_but_not_all(repo, entries, targets)
    change = repo.invalidate_edge(edge_id)
    result = coordinator.handle_change(change)

    after = {p.path_id for p in coordinator.dependency_index.all_paths()}
    assert result.applied is True
    assert result.dropped_path_ids                  # something was removed
    assert after < before and after                 # alternates remain
    # Coordinator state equals a from-scratch P3 run on the new graph.
    fresh = discover_paths(repo.snapshot(), entries, targets, PathOptions()).paths
    assert after == {p.path_id for p in fresh}


def test_p5_ignores_replayed_change():
    repo, entries, targets, coordinator = _setup()
    coordinator.initialize()
    edge_id = _edge_that_blocks_some_but_not_all(repo, entries, targets)
    change = repo.invalidate_edge(edge_id)
    assert coordinator.handle_change(change).applied is True
    replay = repo.invalidate_edge(edge_id)          # same write again
    assert coordinator.handle_change(replay).applied is False


def test_p5_verifier_distinguishes_simulated_from_real():
    repo, entries, targets, _ = _setup()
    search = partial(discover_paths, entry_points=entries, targets=targets)
    snap = repo.snapshot()
    edge_id = _edge_that_blocks_some_but_not_all(repo, entries, targets)
    live_before = _live(search(snap).paths)
    forked = snap.fork((edge_id,))
    blocked = sorted(live_before - _live(search(forked).paths))

    plan = RemediationPlan(id="plan_x", base_version=snap.version, removed_edge_ids=(edge_id,))
    rec = RemediationRecommendation(
        recommendation_id="rec_x", graph_version=snap.version, action_type="remove_edge",
        target_id=edge_id, expected_blocked_path_ids=blocked,
        verification_status=VerificationStatus.SIMULATED,
    )
    verifier = RemediationVerifier(search)
    verifier.register(rec, plan, snap)

    simulated = verifier.verify_remediation(
        "rec_x", after_snapshot=forked, evidence=SourceEvidence.SIMULATION
    )
    assert simulated.status == VerificationStatus.SIMULATED

    repo.invalidate_edge(edge_id)
    real = verifier.verify_remediation(
        "rec_x", after_snapshot=repo.snapshot(), evidence=SourceEvidence.SOURCE_CONFIRMED
    )
    assert real.status == VerificationStatus.VERIFIED
    assert real.alternate_routes_remain is True