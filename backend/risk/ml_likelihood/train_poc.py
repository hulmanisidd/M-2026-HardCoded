"""Train and save the PROOF-OF-CONCEPT model (synthetic labels).

Run from repo root:  python -m backend.risk.ml_likelihood.train_poc
Same seed, data size and split as backend/evaluation/ml_likelihood_eval.py.
"""
from __future__ import annotations

from .interface import DEFAULT_ARTIFACT_DIR, DEFAULT_ARTIFACT_NAME, clear_model_cache
from .model import split_indices, train_logistic
from .persistence import save_model
from .synthetic import generate_synthetic_dataset

SEED, N = 0, 6000


def main() -> None:
    ds = generate_synthetic_dataset(N, seed=SEED)
    tr, ca, _ = split_indices(ds.y, seed=SEED)
    base, _ = train_logistic(ds.X[tr], ds.y[tr], ds.feature_names, seed=SEED)
    model = base.with_calibration("platt", ds.X[ca], ds.y[ca])
    path = save_model(model, DEFAULT_ARTIFACT_DIR, DEFAULT_ARTIFACT_NAME, trained_on="synthetic",
                      model_version="logreg-platt-synthetic-v1", data_meta=ds.meta)
    clear_model_cache()
    print(f"saved {path}  (SYNTHETIC proof of concept; not real attack probabilities)")


if __name__ == "__main__":
    main()