"""Tests for backend/risk/ml_likelihood (PROOF-OF-CONCEPT, synthetic-trained).

These tests check behaviour and failure handling. They do NOT validate real-world
attack probabilities; none exist. Models are trained on tiny synthetic data inside
the tests, so nothing depends on the committed artifact file.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import numpy as np
import pytest

from backend.risk.ml_likelihood import (
    MLLikelihoodEstimate, ModelLoadError, estimate_likelihood, estimate_many, load_model, save_model,
)
from backend.risk.ml_likelihood import interface
from backend.risk.ml_likelihood.features import FEATURE_NAMES, extract_features
from backend.risk.ml_likelihood.model import split_indices, train_logistic
from backend.risk.ml_likelihood.synthetic import _make_one, generate_synthetic_dataset
from contracts import (
    AttackPath, Criticality, EdgeStatus, Entity, FeasibilityStatus, GraphSnapshot, NodeType,
    RelationType, Relationship, make_path_id,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


# ----------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def dataset():
    return generate_synthetic_dataset(800, seed=3)


@pytest.fixture(scope="module")
def model(dataset):
    tr, ca, _ = split_indices(dataset.y, seed=3)
    base, _ = train_logistic(dataset.X[tr], dataset.y[tr], dataset.feature_names, seed=3, c_grid=(0.1, 1.0))
    m = base.with_calibration("platt", dataset.X[ca], dataset.y[ca])
    m.meta.update({"model_version": "test-v1", "trained_on": "synthetic"})
    return m


def make_graph(statuses=(EdgeStatus.CONFIRMED, EdgeStatus.CONFIRMED), crit=Criticality.HIGH,
               feasibility=FeasibilityStatus.FEASIBLE_UNDER_MODEL, version="v1"):
    n = len(statuses)
    ents = [Entity(entity_id="u", entity_type=NodeType.IAM_USER, name="u")]
    ents += [Entity(entity_id=f"r{i}", entity_type=NodeType.IAM_ROLE, name=f"r{i}") for i in range(1, n)]
    ents.append(Entity(entity_id="b", entity_type=NodeType.S3_BUCKET, name="b", criticality=crit))
    ids = [e.entity_id for e in ents]
    edges = []
    for i, st in enumerate(statuses):
        rel = RelationType.CAN_READ if i == n - 1 else RelationType.CAN_ASSUME
        edges.append(Relationship(source_id=ids[i], target_id=ids[i + 1], relation_type=rel, status=st))
    snap = GraphSnapshot(version=version, created_at=NOW, entities=tuple(ents), edges=tuple(edges))
    path = AttackPath(
        path_id=make_path_id(tuple(e.edge_id for e in edges)), graph_version=version,
        entry_node_id="u", target_node_id="b", node_ids=tuple(ids),
        edge_ids=tuple(e.edge_id for e in edges), feasibility_status=feasibility)
    return path, snap


# ------------------------------------------------------------ feature extraction
def test_features_complete_and_ordered():
    path, snap = make_graph()
    res = extract_features(path, snap)
    assert res.ok and res.unknowns == []
    assert tuple(res.features) == FEATURE_NAMES
    assert res.features["hops"] == 2.0
    assert res.features["n_confirmed"] == 2.0
    assert res.features["target_is_s3_bucket"] == 1.0
    assert res.features["target_criticality"] == 3.0


@pytest.mark.parametrize("status", [EdgeStatus.UNKNOWN, EdgeStatus.INVALIDATED])
def test_bad_edge_status_gives_no_features(status):
    path, snap = make_graph(statuses=(EdgeStatus.CONFIRMED, status))
    res = extract_features(path, snap)
    assert res.features is None
    assert any(status.value.upper() in u for u in res.unknowns)


def test_unknown_target_criticality_gives_no_features():
    path, snap = make_graph(crit=None)
    res = extract_features(path, snap)
    assert res.features is None and any("criticality" in u for u in res.unknowns)


def test_edge_missing_from_snapshot():
    path, snap = make_graph()
    smaller = GraphSnapshot(version="v1", created_at=NOW, entities=snap.entities, edges=snap.edges[:1])
    res = extract_features(path, smaller)
    assert res.features is None and any("not in snapshot" in u for u in res.unknowns)


def test_entities_missing_from_snapshot():
    path, snap = make_graph()
    other = GraphSnapshot(version="v1", created_at=NOW,
                          entities=(Entity(entity_id="zz", entity_type=NodeType.IAM_USER, name="zz"),))
    res = extract_features(path, other)
    assert res.features is None
    assert any("target entity" in u for u in res.unknowns) and any("entry entity" in u for u in res.unknowns)


def test_graph_version_mismatch():
    path, snap = make_graph()
    other = GraphSnapshot(version="v2", created_at=NOW, entities=snap.entities, edges=snap.edges)
    res = extract_features(path, other)
    assert res.features is None and any("graph" in u for u in res.unknowns)


def test_blocked_path_has_no_features():
    path, snap = make_graph(feasibility=FeasibilityStatus.BLOCKED)
    res = extract_features(path, snap)
    assert res.features is None and any("BLOCKED" in u for u in res.unknowns)


def test_extract_rejects_wrong_types():
    path, snap = make_graph()
    with pytest.raises(TypeError):
        extract_features("not a path", snap)
    with pytest.raises(TypeError):
        extract_features(None, snap)
    with pytest.raises(TypeError):
        extract_features(path, "not a snapshot")
    with pytest.raises(TypeError):
        extract_features(path, None)


# ------------------------------------------------------------ prediction output
def test_prediction_output_shape_and_metadata(model):
    path, snap = make_graph()
    est = estimate_likelihood(path, snap, model)
    assert isinstance(est, MLLikelihoodEstimate)
    assert est.path_id == path.path_id and est.graph_version == "v1"
    assert 0.0 <= est.probability <= 1.0
    assert est.unknowns == []
    assert est.model_version == "test-v1" and est.trained_on == "synthetic"
    assert est.is_calibrated is True
    assert est.validated_against_real_outcomes is False
    assert "SYNTHETIC" in est.disclaimer


def test_prediction_is_deterministic(model):
    path, snap = make_graph()
    assert estimate_likelihood(path, snap, model) == estimate_likelihood(path, snap, model)


def test_missing_evidence_returns_none_not_a_number(model):
    path, snap = make_graph(statuses=(EdgeStatus.CONFIRMED, EdgeStatus.UNKNOWN))
    est = estimate_likelihood(path, snap, model)
    assert est.probability is None
    assert est.unknowns
    assert est.trained_on == "synthetic" and est.path_id == path.path_id


def test_estimate_many_keeps_order_and_length(model):
    """One snapshot, two different paths: one fully evidenced, one through an UNKNOWN edge."""
    ents = (
        Entity(entity_id="u", entity_type=NodeType.IAM_USER, name="u"),
        Entity(entity_id="r1", entity_type=NodeType.IAM_ROLE, name="r1"),
        Entity(entity_id="r2", entity_type=NodeType.IAM_ROLE, name="r2"),
        Entity(entity_id="b", entity_type=NodeType.S3_BUCKET, name="b", criticality=Criticality.HIGH),
    )

    def rel(s, t, r, st):
        return Relationship(source_id=s, target_id=t, relation_type=r, status=st)

    A, R = RelationType.CAN_ASSUME, RelationType.CAN_READ
    good = [rel("u", "r1", A, EdgeStatus.CONFIRMED), rel("r1", "b", R, EdgeStatus.CONFIRMED)]
    bad = [rel("u", "r2", A, EdgeStatus.UNKNOWN), rel("r2", "b", R, EdgeStatus.CONFIRMED)]
    snap = GraphSnapshot(version="v1", created_at=NOW, entities=ents, edges=tuple(good + bad))

    def mk(nodes, edges):
        return AttackPath(
            path_id=make_path_id(tuple(e.edge_id for e in edges)), graph_version="v1",
            entry_node_id="u", target_node_id="b", node_ids=nodes,
            edge_ids=tuple(e.edge_id for e in edges),
            feasibility_status=FeasibilityStatus.FEASIBLE_UNDER_MODEL)

    p_good, p_bad = mk(("u", "r1", "b"), good), mk(("u", "r2", "b"), bad)
    assert p_good.path_id != p_bad.path_id
    out = estimate_many([p_good, p_bad, p_good], snap, model)
    assert [e.path_id for e in out] == [p_good.path_id, p_bad.path_id, p_good.path_id]
    assert out[0].probability is not None and out[2].probability == out[0].probability
    assert out[1].probability is None and out[1].unknowns


def test_longer_paths_score_lower_on_average(model, dataset):
    hops = dataset.X[:, dataset.feature_names.index("hops")]
    p = model.predict_proba(dataset.X)
    assert p[hops == 1].mean() > p[hops == 5].mean()


def test_estimate_is_separate_from_rule_based_and_impact():
    fields = set(MLLikelihoodEstimate.model_fields)
    assert not {"impact_score", "risk_score", "likelihood_score", "impact"} & fields


# ------------------------------------------------------------ invalid inputs
def test_estimate_rejects_wrong_input_types(model):
    path, snap = make_graph()
    with pytest.raises(TypeError):
        estimate_likelihood("x", snap, model)
    with pytest.raises(TypeError):
        estimate_likelihood(path, None, model)
    with pytest.raises(TypeError):
        estimate_likelihood(path, snap, "not a model")


def test_model_rejects_bad_arrays(model):
    with pytest.raises(ValueError):
        model.predict_proba(np.zeros((1, 5)))
    bad = np.zeros((1, len(FEATURE_NAMES)))
    bad[0, 0] = np.nan
    with pytest.raises(ValueError):
        model.predict_proba(bad)


def test_train_rejects_invalid_data(dataset):
    X, names = dataset.X, dataset.feature_names
    with pytest.raises(ValueError):
        train_logistic(X, np.zeros(len(X), dtype=int), names)           # one class only
    with pytest.raises(ValueError):
        train_logistic(X[:, :5], dataset.y, names)                       # column mismatch
    Xn = X.copy()
    Xn[0, 0] = np.nan
    with pytest.raises(ValueError):
        train_logistic(Xn, dataset.y, names)
    with pytest.raises(ValueError):
        train_logistic(X, dataset.y[:-1], names)                         # length mismatch


def test_synthetic_generator_validation_and_determinism():
    with pytest.raises(ValueError):
        generate_synthetic_dataset(3)
    a, b = generate_synthetic_dataset(50, seed=1), generate_synthetic_dataset(50, seed=1)
    assert np.array_equal(a.X, b.X) and np.array_equal(a.y, b.y)
    assert set(np.unique(a.y)) <= {0, 1} and "SYNTHETIC" in a.meta["disclaimer"]


def test_grouped_split_keeps_groups_together():
    y = np.array([0, 1] * 100)
    groups = np.repeat(np.arange(50), 4)
    tr, ca, te = split_indices(y, groups=groups, seed=0)
    g = [set(groups[i]) for i in (tr, ca, te)]
    assert not (g[0] & g[1]) and not (g[0] & g[2]) and not (g[1] & g[2])


# ------------------------------------------------------------ model loading
def _saved(model, tmp_path, name="m"):
    save_model(model, tmp_path, name, trained_on="synthetic", model_version="test-v1")
    return name


def test_save_load_roundtrip_gives_identical_predictions(model, dataset, tmp_path):
    name = _saved(model, tmp_path)
    loaded = load_model(tmp_path, name)
    assert np.allclose(loaded.predict_proba(dataset.X[:50]), model.predict_proba(dataset.X[:50]))
    assert loaded.meta["model_version"] == "test-v1" and loaded.meta["trained_on"] == "synthetic"
    assert loaded.calibration_method == "platt"


def test_load_missing_files(tmp_path):
    with pytest.raises(ModelLoadError):
        load_model(tmp_path, "nope")


def test_load_detects_corrupted_binary(model, tmp_path):
    name = _saved(model, tmp_path)
    with open(tmp_path / f"{name}.joblib", "ab") as f:
        f.write(b"x")
    with pytest.raises(ModelLoadError, match="checksum"):
        load_model(tmp_path, name)


def test_load_rejects_bad_metadata(model, tmp_path):
    name = _saved(model, tmp_path)
    meta_path = tmp_path / f"{name}.json"
    good = json.loads(meta_path.read_text())

    meta_path.write_text("{not json")
    with pytest.raises(ModelLoadError):
        load_model(tmp_path, name)

    meta_path.write_text(json.dumps({k: v for k, v in good.items() if k != "sha256"}))
    with pytest.raises(ModelLoadError, match="sha256"):
        load_model(tmp_path, name)

    meta_path.write_text(json.dumps({**good, "feature_names": good["feature_names"][:-1]}))
    with pytest.raises(ModelLoadError, match="feature"):
        load_model(tmp_path, name)

    meta_path.write_text(json.dumps({**good, "sklearn_version": "0.1.0"}))
    with pytest.raises(ModelLoadError, match="scikit-learn"):
        load_model(tmp_path, name)


def test_save_rejects_bad_trained_on(model, tmp_path):
    with pytest.raises(ValueError):
        save_model(model, tmp_path, "m", trained_on="magic", model_version="v")


def test_default_model_loaded_from_artifact_dir(model, tmp_path, monkeypatch):
    _saved(model, tmp_path, name="art")
    monkeypatch.setattr(interface, "DEFAULT_ARTIFACT_DIR", tmp_path)
    monkeypatch.setattr(interface, "DEFAULT_ARTIFACT_NAME", "art")
    interface.clear_model_cache()
    try:
        path, snap = make_graph()
        est = estimate_likelihood(path, snap)          # model=None -> default artifact
        assert est.probability is not None and est.model_version == "test-v1"
    finally:
        interface.clear_model_cache()


def test_missing_default_artifact_raises_instead_of_guessing(tmp_path, monkeypatch):
    monkeypatch.setattr(interface, "DEFAULT_ARTIFACT_DIR", tmp_path)
    interface.clear_model_cache()
    try:
        path, snap = make_graph()
        with pytest.raises(ModelLoadError):
            estimate_likelihood(path, snap)
        with pytest.raises(ModelLoadError):
            estimate_many([path], snap)
    finally:
        interface.clear_model_cache()


def test_generator_paths_pass_through_real_extractor():
    rng = np.random.default_rng(0)
    for i in range(20):
        path, snap, _ = _make_one(rng, i)
        assert extract_features(path, snap).ok