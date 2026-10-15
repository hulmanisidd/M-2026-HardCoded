"""Save / load a trained model with integrity and compatibility checks.

Two files per model:  <name>.joblib (the sklearn objects)  and  <name>.json (metadata).
On load we verify: both files exist, the checksum matches, the feature list is
identical to the current code's FEATURE_NAMES, and scikit-learn major.minor matches.

SECURITY NOTE: joblib uses pickle. The checksum catches corruption and accidental
mix-ups; it does NOT make an untrusted file safe. Only load artifacts you produced
or reviewed.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import sklearn

from .features import FEATURE_NAMES
from .model import TrainedModel


class ModelLoadError(RuntimeError):
    """Model artifact is missing, corrupted, or incompatible with this code."""


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _mm(v: str) -> str:
    return ".".join(v.split(".")[:2])


def save_model(model: TrainedModel, directory: str | Path, name: str, *, trained_on: str,
               model_version: str, data_meta: dict | None = None) -> Path:
    if trained_on not in ("synthetic", "real"):
        raise ValueError("trained_on must be 'synthetic' or 'real'")
    if tuple(model.feature_names) != FEATURE_NAMES:
        raise ValueError("model feature_names do not match current FEATURE_NAMES")
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    bin_path, meta_path = d / f"{name}.joblib", d / f"{name}.json"
    joblib.dump({"scaler": model.scaler, "clf": model.clf, "calibrator": model._calibrator}, bin_path)
    meta = {
        "model_version": model_version, "trained_on": trained_on,
        "calibration_method": model.calibration_method, "feature_names": list(model.feature_names),
        "sklearn_version": sklearn.__version__, "sha256": _sha256(bin_path),
        "created_at": datetime.now(timezone.utc).isoformat(), "train_meta": model.meta,
        "data_meta": data_meta or {},
    }
    meta_path.write_text(json.dumps(meta, indent=2, default=str))
    return bin_path


def load_model(directory: str | Path, name: str) -> TrainedModel:
    d = Path(directory)
    bin_path, meta_path = d / f"{name}.joblib", d / f"{name}.json"
    if not bin_path.exists() or not meta_path.exists():
        raise ModelLoadError(f"model files not found: {bin_path} / {meta_path}")
    try:
        meta = json.loads(meta_path.read_text())
    except json.JSONDecodeError as e:
        raise ModelLoadError(f"metadata is not valid JSON: {e}") from e
    for key in ("model_version", "trained_on", "feature_names", "sha256", "sklearn_version"):
        if key not in meta:
            raise ModelLoadError(f"metadata missing '{key}'")
    if _sha256(bin_path) != meta["sha256"]:
        raise ModelLoadError("checksum mismatch: model file was modified or corrupted")
    if tuple(meta["feature_names"]) != FEATURE_NAMES:
        raise ModelLoadError("feature list in artifact differs from current FEATURE_NAMES; retrain the model")
    if _mm(meta["sklearn_version"]) != _mm(sklearn.__version__):
        raise ModelLoadError(
            f"artifact built with scikit-learn {meta['sklearn_version']}, running {sklearn.__version__}; "
            "retrain with `python -m backend.risk.ml_likelihood.train_poc`")
    try:
        parts = joblib.load(bin_path)
        m = TrainedModel(FEATURE_NAMES, parts["scaler"], parts["clf"], meta.get("calibration_method"),
                         parts.get("calibrator"), {"model_version": meta["model_version"],
                                                    "trained_on": meta["trained_on"]})
    except Exception as e:  # unpicklable / wrong structure
        raise ModelLoadError(f"could not deserialise model: {e}") from e
    return m