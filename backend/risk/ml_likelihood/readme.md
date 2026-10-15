# ML likelihood estimator (proof of concept)

> **STATUS: PROOF OF CONCEPT. The model is trained on SYNTHETIC labels generated from
> assumed coefficients. Its outputs are NOT real-world attack probabilities, and nothing in
> this folder has been validated against real attack outcomes.** No real outcome data
> exists in this repository.

A separate, optional likelihood estimate for an `AttackPath`, produced by logistic
regression. It is **independent of** the rule-based score in `backend/remediation/scoring.py`
and of impact scoring, so the team can compare the two approaches. It does not modify the
graph, path-discovery or remediation modules, and nothing in `contracts/` changed.

## Prediction target

> **y = 1** if an attacker starting at `entry_node_id`, within a fixed observation window
> (nominally 30 days), successfully reaches `target_node_id` using exactly this path;
> **y = 0** if the path existed and was not exploited in that window.

The model estimates `P(y = 1 | path features)`. `BLOCKED` paths are out of scope.

## Interface (for Person 4)

```python
from backend.risk.ml_likelihood import estimate_likelihood, estimate_many

est = estimate_likelihood(path, snapshot)       # path: AttackPath, snapshot: GraphSnapshot
est.probability                                 # float in [0, 1], or None if evidence is missing
est.unknowns                                    # list[str]: why probability is None
est.model_version, est.trained_on               # e.g. "logreg-platt-synthetic-v1", "synthetic"
est.is_calibrated                               # True if a calibrator was applied
est.validated_against_real_outcomes             # False for everything built so far
est.disclaimer                                  # carries the synthetic warning

estimates = estimate_many(paths, snapshot)      # same order as `paths`
```

Behaviour contract:

- Missing or untrustworthy evidence (an `UNKNOWN`/`INVALIDATED` edge, an entity or edge
  absent from the snapshot, unknown target criticality, a graph-version mismatch, a
  `BLOCKED` path) gives `probability=None` plus reasons. **No default number is ever
  substituted.** Treat `None` like P4 already treats `likelihood_score=None`.
- Wrong argument types raise `TypeError`. A missing or incompatible model file raises
  `ModelLoadError`; it never silently falls back.
- `MLLikelihoodEstimate` is its own type and has no impact or risk fields. To compare
  with the rule-based score, call both and put them side by side:

```python
from backend.remediation.scoring import assess_path
rule = assess_path(path, snapshot).likelihood_score     # relative route score, not a probability
ml = estimate_likelihood(path, snapshot).probability    # model output, synthetic-trained
```

  The two are on different footings: compare **rankings**, not absolute values.
  Do not multiply `ml` by impact and present the result as a validated risk figure.

## Features (`features.py`, 32 numeric, fixed order `FEATURE_NAMES`)

Hop count; per-relation-type edge counts; counts of confirmed / inferred / stale edges and
of edges with conditions; fraction confirmed; mean evidence ids per edge; path-level
evidence count; whether the path is `CONDITIONAL`; target criticality (ordinal) and target
type (one-hot); whether the entry is an external principal or an IAM user.

Target criticality is used as a *target characteristic* (attackers may prefer valuable
targets). It is not the impact score.

## Model and calibration

Standardised features, L2 logistic regression, `C` chosen by 5-fold cross-validated log
loss on the training split. No class weighting (it would distort probabilities). Platt
scaling is fitted on a separate calibration split. Splits are 60/20/20 train/calibration/test;
`split_indices` supports grouped splits, which are **required** for real data.

## Reproduce

```
pip install numpy pydantic scikit-learn joblib pytest
python -m backend.evaluation.ml_likelihood_eval          # writes backend/evaluation/results/
python -m backend.risk.ml_likelihood.train_poc           # builds artifacts/ (needed by estimate_likelihood)
python -m pytest tests/unit/test_ml_likelihood.py -q
```

Seed, data size and split are fixed, so the evaluation output is byte-identical between runs.
On Windows PowerShell, before running the full suite: `$env:PYTHONPATH = "tests/unit"`.

## Results (synthetic test split, seed 0, n = 6000; see `backend/evaluation/results/`)

| model | ROC AUC | Brier | ECE |
|---|---|---|---|
| constant base rate | 0.500 | 0.202 | 0.000 |
| rule-based (P4), ranking only | 0.729 | n/a | n/a |
| logreg, uncalibrated | 0.745 | 0.171 | 0.032 |
| logreg, Platt (default) | 0.745 | 0.171 | 0.029 |

These show the pipeline works end to end. They do **not** show the model is accurate on
real attacks, and the ML-vs-rule-based gap is **not evidence that ML is better**: the
labels come from coefficients we wrote, which differ from P4's weights.

Under a prior-shift stress test (same feature relationships, different base rate, model
not refit) ECE rose from about 0.01 to about 0.14-0.16. Calibration holds only when
deployment resembles the training distribution.

## Limitations

1. **Synthetic labels.** Coefficients in `synthetic.py` (`ASSUMED`) are team assumptions.
   The model learns them back; coefficients and feature importances reflect the generator,
   not reality.
2. **No real validation.** Calibration was checked on held-out synthetic data only. Probabilities
   must not be described as actual attack probabilities until validated on real outcomes.
3. **Prior shift.** Calibration degrades when the base exploitation rate differs from training.
4. **Selection bias in real data.** Untested paths are not negatives; red-team outcomes reflect
   the red team, not real attackers (see `DATA_REQUIREMENTS.md`).
5. **Model class.** Logistic regression is linear in these features; interactions and
   graph-structural effects (e.g. shared nodes across paths) are not modelled. Paths on the same
   graph are not independent; real evaluation needs grouped splits.
6. **Scope.** `BLOCKED` paths and paths with unknown evidence get no estimate. Scores are
   computed per path, not for combined or chained attacks.
7. **Artifact format.** Models are pickled via joblib and tied to the scikit-learn major.minor
   version. The checksum detects corruption, not tampering; only load artifacts you trust.

## Moving to real data

Follow `DATA_REQUIREMENTS.md`: fix the observation window, collect labelled
(path, snapshot, outcome) records with their source, use grouped splits, re-run the same
evaluation, and only then change `trained_on` to `"real"` and consider
`validated_against_real_outcomes=True` (that flag is currently hard-wired to `False`).

## Files

`features.py` extraction · `synthetic.py` proof-of-concept data · `model.py` training and
calibration · `persistence.py` save/load with checks · `interface.py` public API ·
`train_poc.py` builds the artifact · `backend/evaluation/ml_likelihood_eval.py` evaluation ·
`tests/unit/test_ml_likelihood.py` tests.