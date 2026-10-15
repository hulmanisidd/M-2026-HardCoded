"""Tests for P5 remediation verification (uses the real seed graph, P3 and P4)."""

import pytest

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.seed_data import ENTRY_KEYS, TARGET_KEYS, load_into
from backend.paths import discover_paths
from backend.remediation.candidates import generate_candidates
from backend.remediation.simulation import recommend
from backend.updates.verification import RemediationVerifier, SourceEvidence
from contracts import PathOptions
from functools import partial
from contracts.remediation import VerificationStatus


def _setup():
    repo = InMemoryGraphRepository()
    seed = load_into(repo)
    entries = [seed.entity_ids[k] for k in ENTRY_KEYS]
    targets = [seed.entity_ids[k] for k in TARGET_KEYS]

    search = partial(
        discover_paths, entry_points=entries, targets=targets, options=PathOptions()
    )

    def finder(snapshot):
        return list(search(snapshot).paths)

    snap = repo.snapshot()
    paths = finder(snap)
    candidate = generate_candidates(paths, snap)[0]
    rec = recommend(candidate, snap, finder)
    verifier = RemediationVerifier(search)
    verifier.register(rec, candidate.plan, snap)
    return repo, snap, candidate, rec, verifier, search


def _forked(snap, candidate):
    return snap.fork(candidate.plan.removed_edge_ids)


def test_simulation_is_never_reported_as_verified():
    _, snap, cand, rec, verifier, _ = _setup()
    out = verifier.verify_remediation(
        rec.recommendation_id,
        after_snapshot=_forked(snap, cand),
        evidence=SourceEvidence.SIMULATION,
    )
    assert out.status == VerificationStatus.SIMULATED
    assert set(rec.expected_blocked_path_ids) <= set(out.blocked_path_ids)


@pytest.mark.parametrize(
    "evidence, expected",
    [
        (SourceEvidence.SOURCE_CONFIRMED, VerificationStatus.VERIFIED),
        (SourceEvidence.SOURCE_STALE, VerificationStatus.PARTIALLY_VERIFIED),
        (SourceEvidence.SOURCE_UNAVAILABLE, VerificationStatus.UNKNOWN),
        (SourceEvidence.SIMULATION, VerificationStatus.SIMULATED),
    ],
)
def test_status_depends_on_source_evidence(evidence, expected):
    _, snap, cand, rec, verifier, _ = _setup()
    out = verifier.verify_remediation(
        rec.recommendation_id, after_snapshot=_forked(snap, cand), evidence=evidence
    )
    assert out.status == expected


def test_real_invalidation_with_confirmed_source_is_verified_and_shows_alternates():
    repo, snap, cand, rec, verifier, _ = _setup()
    for edge_id in cand.plan.removed_edge_ids:
        repo.invalidate_edge(edge_id)
    out = verifier.verify_remediation(
        rec.recommendation_id,
        after_snapshot=repo.snapshot(),
        evidence=SourceEvidence.SOURCE_CONFIRMED,
    )
    assert out.status == VerificationStatus.VERIFIED
    assert out.alternate_routes_remain is True     # other routes must stay visible
    assert out.residual_path_ids


def test_fix_not_applied_fails_verification():
    repo, snap, cand, rec, verifier, _ = _setup()
    # A new snapshot version with nothing removed: the "fix" never happened.
    other = snap.model_copy(update={"version": "g_unchanged_copy"})
    out = verifier.verify_remediation(
        rec.recommendation_id,
        after_snapshot=other,
        evidence=SourceEvidence.SOURCE_CONFIRMED,
    )
    assert out.status == VerificationStatus.FAILED
    assert out.still_open_path_ids


def test_new_path_after_fix_fails():
    _, snap, cand, rec, _, search = _setup()
    after = _forked(snap, cand)

    def search_with_extra(s):
        res = search(s)
        if s.version == after.version and res.paths:
            extra = res.paths[0].model_copy(update={"path_id": "p_brand_new"})
            return res.model_copy(update={"paths": res.paths + (extra,)})
        return res

    verifier = RemediationVerifier(search_with_extra)
    verifier.register(rec, cand.plan, snap)
    out = verifier.verify_remediation(
        rec.recommendation_id,
        after_snapshot=after,
        evidence=SourceEvidence.SOURCE_CONFIRMED,
    )
    assert out.status == VerificationStatus.FAILED
    assert "p_brand_new" in out.new_path_ids


def test_stale_recommendation_version_is_unknown():
    _, snap, cand, rec, verifier, _ = _setup()
    stale_rec = rec.model_copy(update={"graph_version": "g_old"})
    verifier.register(stale_rec, cand.plan, snap)
    out = verifier.verify_remediation(
        stale_rec.recommendation_id,
        after_snapshot=_forked(snap, cand),
        evidence=SourceEvidence.SOURCE_CONFIRMED,
    )
    assert out.status == VerificationStatus.UNKNOWN


def test_same_version_after_state_is_unknown():
    _, snap, _, rec, verifier, _ = _setup()
    out = verifier.verify_remediation(
        rec.recommendation_id,
        after_snapshot=snap,
        evidence=SourceEvidence.SOURCE_CONFIRMED,
    )
    assert out.status == VerificationStatus.UNKNOWN


def test_unknown_recommendation_id_raises():
    _, snap, _, _, verifier, _ = _setup()
    with pytest.raises(KeyError):
        verifier.verify_remediation(
            "nope", after_snapshot=snap, evidence=SourceEvidence.SIMULATION
        )


def _verifier_with_options(snap, cand, rec, **opt):
    repo = InMemoryGraphRepository()
    seed = load_into(repo)
    entries = [seed.entity_ids[k] for k in ENTRY_KEYS]
    targets = [seed.entity_ids[k] for k in TARGET_KEYS]
    search = partial(
        discover_paths, entry_points=entries, targets=targets,
        options=PathOptions(**opt),
    )
    v = RemediationVerifier(search)
    v.register(rec, cand.plan, snap)
    return v


def test_truncated_search_cannot_be_fully_verified():
    _, snap, cand, rec, _, _ = _setup()
    verifier = _verifier_with_options(snap, cand, rec, max_paths=1)
    out = verifier.verify_remediation(
        rec.recommendation_id,
        after_snapshot=_forked(snap, cand),
        evidence=SourceEvidence.SOURCE_CONFIRMED,
    )
    assert out.status == VerificationStatus.PARTIALLY_VERIFIED
    assert any("truncated" in r for r in out.reasons)


def test_unknown_target_cannot_be_fully_verified():
    _, snap, cand, rec, _, _ = _setup()
    repo = InMemoryGraphRepository()
    seed = load_into(repo)
    entries = [seed.entity_ids[k] for k in ENTRY_KEYS]
    targets = [seed.entity_ids[k] for k in TARGET_KEYS] + ["arn:aws:s3:::missing"]
    search = partial(
        discover_paths, entry_points=entries, targets=targets, options=PathOptions()
    )
    verifier = RemediationVerifier(search)
    verifier.register(rec, cand.plan, snap)
    out = verifier.verify_remediation(
        rec.recommendation_id,
        after_snapshot=_forked(snap, cand),
        evidence=SourceEvidence.SOURCE_CONFIRMED,
    )
    assert out.status == VerificationStatus.PARTIALLY_VERIFIED
    assert any("unknown entry/target" in r for r in out.reasons)