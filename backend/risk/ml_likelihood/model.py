"""Logistic-regression likelihood model with optional probability calibration.

Design choices (each is deliberate):
  * StandardScaler + L2 LogisticRegression. Interpretable, fast, a sensible baseline.
  * NO class_weight: reweighting classes would distort the predicted probabilities,
    and we want to present (and check) them as probabilities.
  * Regularisation strength C is picked by cross-validated LOG LOSS (a proper scoring rule)
    on the training split only.
  * Calibration (Platt scaling by default) is fit on a SEPARATE calibration split, never
    on the data the base model was trained on, and is evaluated on a third untouched split.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score, GroupShuffleSplit, train_test_split
from sklearn.preprocessing import StandardScaler

C_GRID = (0.01, 0.1, 1.0, 10.0)


@dataclass
class TrainedModel:
    feature_names: tuple[str, ...]
    scaler: StandardScaler
    clf: LogisticRegression
    calibration_method: str | None = None          # None | "platt" | "isotonic"
    _calibrator: object = None
    meta: dict = field(default_factory=dict)

    def _check(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        if X.ndim != 2 or X.shape[1] != len(self.feature_names):
            raise ValueError(f"X must have shape (n, {len(self.feature_names)}), got {X.shape}")
        if not np.isfinite(X).all():
            raise ValueError("X contains NaN or inf; missing features must be handled before prediction")
        return X

    def decision_scores(self, X: np.ndarray) -> np.ndarray:
        return self.clf.decision_function(self.scaler.transform(self._check(X)))

    def predict_raw(self, X: np.ndarray) -> np.ndarray:
        """Uncalibrated model probabilities."""
        return self.clf.predict_proba(self.scaler.transform(self._check(X)))[:, 1]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Calibrated if a calibrator was fitted, otherwise raw."""
        return self._apply_calibrator(self.decision_scores(X))

    def _apply_calibrator(self, scores: np.ndarray) -> np.ndarray:
        if self.calibration_method is None:
            return 1.0 / (1.0 + np.exp(-scores))
        if self.calibration_method == "platt":
            return self._calibrator.predict_proba(scores.reshape(-1, 1))[:, 1]
        return self._calibrator.predict(scores)

    def with_calibration(self, method: str | None, X_cal: np.ndarray, y_cal: np.ndarray) -> "TrainedModel":
        """Return a copy calibrated on a held-out calibration split."""
        if method not in (None, "platt", "isotonic"):
            raise ValueError("method must be None, 'platt' or 'isotonic'")
        cal = None
        if method is not None:
            s = self.decision_scores(X_cal)
            if method == "platt":
                cal = LogisticRegression(C=1e6).fit(s.reshape(-1, 1), y_cal)   # ~unregularised
            else:
                cal = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(s, y_cal)
        return TrainedModel(self.feature_names, self.scaler, self.clf, method, cal, dict(self.meta))

    def coefficients(self) -> list[tuple[str, float]]:
        """(feature, standardised coefficient), sorted by |coef|. Interpret with care."""
        pairs = list(zip(self.feature_names, self.clf.coef_[0]))
        return sorted(pairs, key=lambda t: -abs(t[1]))


def split_indices(y: np.ndarray, groups: np.ndarray | None = None, seed: int = 0,
                  frac=(0.6, 0.2, 0.2)) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """train / calibration / test indices.

    With `groups` (e.g. account_id or graph snapshot id) whole groups stay together, which
    is REQUIRED for real data to avoid leakage between near-identical paths. Synthetic
    samples are i.i.d., so stratified splitting is used when groups is None.
    """
    n = len(y)
    idx = np.arange(n)
    if groups is None:
        tr, rest = train_test_split(idx, train_size=frac[0], stratify=y, random_state=seed)
        ca, te = train_test_split(rest, train_size=frac[1] / (frac[1] + frac[2]), stratify=y[rest], random_state=seed)
        return tr, ca, te
    groups = np.asarray(groups)
    gss = GroupShuffleSplit(n_splits=1, train_size=frac[0], random_state=seed)
    tr, rest = next(gss.split(idx, y, groups))
    gss2 = GroupShuffleSplit(n_splits=1, train_size=frac[1] / (frac[1] + frac[2]), random_state=seed)
    r_ca, r_te = next(gss2.split(rest, y[rest], groups[rest]))
    return tr, rest[r_ca], rest[r_te]


def train_logistic(X: np.ndarray, y: np.ndarray, feature_names: tuple[str, ...],
                   seed: int = 0, c_grid=C_GRID) -> tuple[TrainedModel, dict]:
    """Fit the base model. Returns (model, {C: mean CV log loss}). Uncalibrated."""
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=int)
    if X.ndim != 2 or X.shape[1] != len(feature_names):
        raise ValueError("X columns must match feature_names")
    if len(y) != len(X) or set(np.unique(y)) - {0, 1} or len(np.unique(y)) < 2:
        raise ValueError("y must be 0/1 with both classes present and the same length as X")
    if not np.isfinite(X).all():
        raise ValueError("X contains NaN or inf")

    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    cv = StratifiedKFold(5, shuffle=True, random_state=seed)
    cv_logloss = {}
    for c in c_grid:
        scores = cross_val_score(LogisticRegression(C=c, max_iter=2000), Xs, y, cv=cv, scoring="neg_log_loss")
        cv_logloss[c] = float(-scores.mean())
    best_c = min(cv_logloss, key=cv_logloss.get)
    clf = LogisticRegression(C=best_c, max_iter=2000).fit(Xs, y)
    return TrainedModel(tuple(feature_names), scaler, clf, meta={"C": best_c, "seed": seed}), cv_logloss