"""Public interface for Person 4.

    from backend.risk.ml_likelihood import estimate_likelihood
    est = estimate_likelihood(path, snapshot)         # uses the default artifact
    est.probability                                   # float in [0, 1] or None

This is SEPARATE from `RiskAssessment` / `PathScore` and from impact. It never
modifies or reads P4's score; P4 may put the two side by side.

`probability` is None (never a guessed number) when required evidence is missing;
the reasons are in `unknowns`.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from contracts import AttackPath, GraphSnapshot

from .features import FEATURE_NAMES, extract_features
from .model import TrainedModel
from .persistence import ModelLoadError, load_model
from .synthetic import SYNTHETIC_DISCLAIMER

DEFAULT_ARTIFACT_DIR = Path(__file__).parent / "artifacts"
DEFAULT_ARTIFACT_NAME = "logreg_synthetic_v1"


class MLLikelihoodEstimate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path_id: str = Field(min_length=1)
    graph_version: str = Field(min_length=1)
    probability: float | None = Field(default=None, ge=0.0, le=1.0)
    unknowns: list[str] = Field(default_factory=list)
    model_version: str
    trained_on: Literal["synthetic", "real"]
    is_calibrated: bool
    # True only when the model was trained on real outcomes AND validated on held-out real data.
    validated_against_real_outcomes: bool = False
    disclaimer: str = ""


@lru_cache(maxsize=1)
def _default_model() -> TrainedModel:
    return load_model(DEFAULT_ARTIFACT_DIR, DEFAULT_ARTIFACT_NAME)


def clear_model_cache() -> None:
    _default_model.cache_clear()


def estimate_likelihood(path: AttackPath, snapshot: GraphSnapshot,
                        model: TrainedModel | None = None) -> MLLikelihoodEstimate:
    """Estimate P(exploited | path) with the ML model.

    Raises TypeError for wrong input types, ModelLoadError if no model can be loaded.
    Returns probability=None (with reasons) if evidence is missing.
    """
    if model is not None and not isinstance(model, TrainedModel):
        raise TypeError(f"model must be TrainedModel or None, got {type(model).__name__}")
    res = extract_features(path, snapshot)          # validates path / snapshot types
    m = model if model is not None else _default_model()
    trained_on = m.meta.get("trained_on", "synthetic")
    common = dict(
        path_id=path.path_id, graph_version=path.graph_version,
        model_version=str(m.meta.get("model_version", "unversioned")), trained_on=trained_on,
        is_calibrated=m.calibration_method is not None,
        validated_against_real_outcomes=False,
        disclaimer=SYNTHETIC_DISCLAIMER if trained_on == "synthetic" else "",
    )
    if not res.ok:
        return MLLikelihoodEstimate(probability=None, unknowns=res.unknowns, **common)
    row = np.array([[res.features[n] for n in FEATURE_NAMES]], dtype=float)
    p = float(np.clip(m.predict_proba(row)[0], 0.0, 1.0))
    return MLLikelihoodEstimate(probability=round(p, 6), unknowns=[], **common)


def estimate_many(paths: list[AttackPath], snapshot: GraphSnapshot,
                  model: TrainedModel | None = None) -> list[MLLikelihoodEstimate]:
    """Same order as `paths`; one estimate per path (None probability where evidence is missing)."""
    if model is None:
        _default_model()    # fail fast, once, if the artifact is missing
    return [estimate_likelihood(p, snapshot, model) for p in paths]