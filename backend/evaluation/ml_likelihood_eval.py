"""Reproducible evaluation of the ML likelihood model on SYNTHETIC data.

Run from repo root:   python -m backend.evaluation.ml_likelihood_eval

!! Results are PROOF-OF-CONCEPT. Labels come from assumed coefficients
!! (backend/risk/ml_likelihood/synthetic.py), so these numbers show that the pipeline
!! works. They do NOT establish real-world attack probabilities.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, log_loss, roc_auc_score

from backend.risk.ml_likelihood.model import split_indices, train_logistic
from backend.risk.ml_likelihood.synthetic import SYNTHETIC_DISCLAIMER, generate_synthetic_dataset

SEED = 0
N = 6000
OUT_DIR = Path(__file__).parent / "results"


def ece(y, p, bins=10):
    """Expected calibration error, equal-width bins."""
    edges = np.linspace(0, 1, bins + 1)
    ids = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    total = 0.0
    for b in range(bins):
        m = ids == b
        if m.any():
            total += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(total)


def reliability(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    ids = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    rows = []
    for b in range(bins):
        m = ids == b
        if m.any():
            rows.append({"bin": f"{edges[b]:.1f}-{edges[b+1]:.1f}", "n": int(m.sum()),
                         "mean_predicted": round(float(p[m].mean()), 3),
                         "observed_rate": round(float(y[m].mean()), 3)})
    return rows


def metrics(y, p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return {"roc_auc": float(roc_auc_score(y, p)), "pr_auc": float(average_precision_score(y, p)),
            "log_loss": float(log_loss(y, p)), "brier": float(brier_score_loss(y, p)), "ece": ece(y, p)}


def bootstrap_ci(y, p, fn, n_boot=500, seed=0):
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n_boot):
        i = rng.integers(0, len(y), len(y))
        if len(np.unique(y[i])) < 2:
            continue
        vals.append(fn(y[i], p[i]))
    return [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]


def main() -> dict:
    ds = generate_synthetic_dataset(N, seed=SEED)
    X, y = ds.X, ds.y
    tr, ca, te = split_indices(y, groups=None, seed=SEED)
    base, cv_ll = train_logistic(X[tr], y[tr], ds.feature_names, seed=SEED)

    variants = {
        "logreg_uncalibrated": base.with_calibration(None, X[ca], y[ca]),
        "logreg_platt": base.with_calibration("platt", X[ca], y[ca]),
        "logreg_isotonic": base.with_calibration("isotonic", X[ca], y[ca]),
    }
    results = {"disclaimer": SYNTHETIC_DISCLAIMER, "dataset": ds.meta,
               "split_sizes": {"train": len(tr), "calibration": len(ca), "test": len(te)},
               "chosen_C": base.meta["C"], "cv_log_loss_by_C": cv_ll, "test_metrics": {}}

    p_const = np.full(len(te), y[tr].mean())
    results["test_metrics"]["baseline_constant_base_rate"] = metrics(y[te], p_const)
    # Rule-based score is a RELATIVE score, not a probability: only ranking metrics are meaningful.
    rs = ds.rule_scores[te]
    results["test_metrics"]["rule_based_P4_ranking_only"] = {
        "roc_auc": float(roc_auc_score(y[te], rs)), "pr_auc": float(average_precision_score(y[te], rs)),
        "note": "not a probability; log loss/Brier/ECE intentionally omitted"}
    for name, m in variants.items():
        p = m.predict_proba(X[te])
        results["test_metrics"][name] = metrics(y[te], p)
    best = variants["logreg_platt"]
    p_best = best.predict_proba(X[te])
    results["bootstrap_95ci_platt"] = {
        "roc_auc": bootstrap_ci(y[te], p_best, roc_auc_score),
        "brier": bootstrap_ci(y[te], p_best, brier_score_loss)}
    results["reliability_platt_test"] = reliability(y[te], p_best)
    results["reliability_uncalibrated_test"] = reliability(y[te], variants["logreg_uncalibrated"].predict_proba(X[te]))

    # 5-fold CV AUC on train+calibration for stability (base model only)
    from sklearn.model_selection import StratifiedKFold
    aucs = []
    pool = np.concatenate([tr, ca])
    for a, b in StratifiedKFold(5, shuffle=True, random_state=SEED).split(X[pool], y[pool]):
        m, _ = train_logistic(X[pool][a], y[pool][a], ds.feature_names, seed=SEED)
        aucs.append(roc_auc_score(y[pool][b], m.predict_raw(X[pool][b])))
    results["cv5_roc_auc_mean_std"] = [float(np.mean(aucs)), float(np.std(aucs))]

    # Prior-shift stress test: same relationships, different base rate. Model NOT refit.
    shift = {}
    for s in (-1.0, 0.0, 1.0):
        d2 = generate_synthetic_dataset(3000, seed=SEED + 1, intercept_shift=s)
        p2 = best.predict_proba(d2.X)
        shift[f"shift_{s:+.1f}"] = {**metrics(d2.y, p2), "observed_base_rate": float(d2.y.mean()),
                                    "mean_predicted": float(p2.mean())}
    results["prior_shift_platt"] = shift
    results["top_coefficients_standardised"] = [(n, round(float(c), 3)) for n, c in base.coefficients()[:10]]
    return results


def to_markdown(r: dict) -> str:
    L = ["# ML likelihood: synthetic proof-of-concept evaluation", "", f"> **{r['disclaimer']}**", "",
         f"Seed {SEED}, n={r['dataset']['n']}, base rate {r['dataset']['base_rate']:.3f}, split {r['split_sizes']}, chosen C={r['chosen_C']}", "",
         "## Test-set metrics (held-out 20%)", "", "| model | ROC AUC | PR AUC | log loss | Brier | ECE |", "|---|---|---|---|---|---|"]
    for k, m in r["test_metrics"].items():
        f = lambda key: f"{m[key]:.3f}" if key in m else "n/a"
        L.append(f"| {k} | {f('roc_auc')} | {f('pr_auc')} | {f('log_loss')} | {f('brier')} | {f('ece')} |")
    L += ["", f"5-fold CV ROC AUC (base model): {r['cv5_roc_auc_mean_std'][0]:.3f} +/- {r['cv5_roc_auc_mean_std'][1]:.3f}",
          f"Bootstrap 95% CI (Platt): AUC {r['bootstrap_95ci_platt']['roc_auc']}, Brier {r['bootstrap_95ci_platt']['brier']}", "",
          "## Reliability (Platt, test)", "", "| bin | n | mean predicted | observed |", "|---|---|---|---|"]
    L += [f"| {b['bin']} | {b['n']} | {b['mean_predicted']} | {b['observed_rate']} |" for b in r["reliability_platt_test"]]
    L += ["", "## Prior-shift stress test (model not refit)", "", "| shift | observed rate | mean predicted | Brier | ECE |", "|---|---|---|---|---|"]
    L += [f"| {k} | {v['observed_base_rate']:.3f} | {v['mean_predicted']:.3f} | {v['brier']:.3f} | {v['ece']:.3f} |" for k, v in r["prior_shift_platt"].items()]
    L += ["", "## Top coefficients (standardised; reflect the ASSUMED generator, not reality)", ""]
    L += [f"- {n}: {c}" for n, c in r["top_coefficients_standardised"]]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    res = main()
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "ml_likelihood_poc.json").write_text(json.dumps(res, indent=2))
    (OUT_DIR / "ml_likelihood_poc.md").write_text(to_markdown(res))
    sys.stdout.write(to_markdown(res))