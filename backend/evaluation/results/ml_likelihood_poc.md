# ML likelihood: synthetic proof-of-concept evaluation

> **SYNTHETIC proof-of-concept data. Labels come from assumed coefficients, not real attack outcomes. Not evidence of real-world attack probability.**

Seed 0, n=6000, base rate 0.281, split {'train': 3600, 'calibration': 1200, 'test': 1200}, chosen C=0.1

## Test-set metrics (held-out 20%)

| model | ROC AUC | PR AUC | log loss | Brier | ECE |
|---|---|---|---|---|---|
| baseline_constant_base_rate | 0.500 | 0.281 | 0.594 | 0.202 | 0.000 |
| rule_based_P4_ranking_only | 0.729 | 0.480 | n/a | n/a | n/a |
| logreg_uncalibrated | 0.745 | 0.538 | 0.513 | 0.171 | 0.032 |
| logreg_platt | 0.745 | 0.538 | 0.513 | 0.171 | 0.029 |
| logreg_isotonic | 0.739 | 0.502 | 0.528 | 0.173 | 0.035 |

5-fold CV ROC AUC (base model): 0.746 +/- 0.020
Bootstrap 95% CI (Platt): AUC [0.7095190868373019, 0.781035409785702], Brier [0.1587152700585904, 0.18210399452043782]

## Reliability (Platt, test)

| bin | n | mean predicted | observed |
|---|---|---|---|
| 0.0-0.1 | 225 | 0.055 | 0.071 |
| 0.1-0.2 | 262 | 0.146 | 0.176 |
| 0.2-0.3 | 215 | 0.247 | 0.237 |
| 0.3-0.4 | 177 | 0.346 | 0.339 |
| 0.4-0.5 | 159 | 0.447 | 0.377 |
| 0.5-0.6 | 101 | 0.549 | 0.584 |
| 0.6-0.7 | 52 | 0.64 | 0.75 |
| 0.7-0.8 | 9 | 0.729 | 0.667 |

## Prior-shift stress test (model not refit)

| shift | observed rate | mean predicted | Brier | ECE |
|---|---|---|---|---|
| shift_-1.0 | 0.143 | 0.286 | 0.135 | 0.142 |
| shift_+0.0 | 0.279 | 0.286 | 0.171 | 0.010 |
| shift_+1.0 | 0.444 | 0.286 | 0.225 | 0.158 |

## Top coefficients (standardised; reflect the ASSUMED generator, not reality)

- n_conditioned: -0.603
- n_stale: -0.357
- target_criticality: 0.276
- n_rel_runs_as: -0.272
- n_inferred: -0.264
- n_confirmed: 0.19
- hops: -0.17
- n_rel_can_modify_policy: 0.146
- n_rel_can_assume: -0.141
- mean_evidence_per_edge: 0.133