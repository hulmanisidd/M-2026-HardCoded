# P4: Risk and Remediation

Ranks attack paths by a relative risk score, proposes fixes (remove an edge), simulates each fix on a graph copy, and picks a set of fixes with a greedy optimizer. P4 only emits `PROPOSED` / `SIMULATED` statuses. It never changes a real system. `VERIFIED` / `APPLIED` belong to P5.

## Inputs

- `paths`: a list of `AttackPath` from P3 (`contracts/`).
- `snapshot`: a `GraphSnapshot` from P2. Paths must have been discovered on the same graph version as the snapshot.
- `find_paths`: a callable `find_paths(snapshot) -> list[AttackPath]`, passed in so P4 can rediscover paths on a forked graph.
- Optional: `RiskConfig` (scoring) and `OptimizerConstraints` (see below).

## Outputs

- `RiskAssessment` per path (`rank_paths`).
- `RemediationRecommendation` per chosen fix (`recommend_fixes`), always with `verification_status = SIMULATED`.
- Plain-text explanations (`explanations.py`).

## Public functions

| Module | Function | Purpose |
|---|---|---|
| `scoring.py` | `rank_paths(paths, snapshot, config=None)` | Score every path |
| `scoring.py` | `assess_path(path, snapshot, config=None)` | Score one path |
| `candidates.py` | `generate_candidates(paths, snapshot, actions=None)` | One candidate fix per removable edge |
| `simulation.py` | `simulate_plan(snapshot, plan, find_paths)` | Apply a plan to a graph copy, return blocked and residual paths |
| `simulation.py` | `recommend(candidate, snapshot, find_paths, config=None)` | Simulate one fix alone |
| `optimizer.py` | `greedy_select(...)` | Greedy fix-set selection |
| `optimizer.py` | `recommend_fixes(paths, assessments, snapshot, constraints=None, *, find_paths, config=None)` | Main entry point |
| `explanations.py` | `explain_assessment`, `explain_fix_set`, `explain_recommendation` | Human-readable text |

## How to read the numbers

- **Risk score** is a relative route score (0-1), not a probability. Nothing here is calibrated against real incident data.
- **Unknown evidence:** a path whose evidence is missing (for example an `UNKNOWN` edge) gets `risk_score = None`, confidence `unknown`, and entries in `unknowns`. It stays in the residual paths and is excluded from risk totals. It is never counted as zero risk.
- **`estimated_risk_reduction`** is a fraction of the known baseline risk: `blocked risk / known total`, from 0 to 1. It is not an absolute score. A fix that blocks only unknown-risk paths gets exactly `0.0`.
- **`estimated_cost`** and **disruption** are 0-1 assumptions from `DEFAULT_ACTIONS` in `candidates.py`, not measured values. They need team review.
- **Per-recommendation numbers** describe that fix simulated alone. They overlap when fixes share paths. Set-level cost and risk are in the recommendation's `assumptions`.

## Optimizer

- Greedy: each round picks the best marginal fix. It is an approximation, not guaranteed globally optimal.
- Constraints (`OptimizerConstraints`): `max_total_cost`, `max_disruption_per_action`, `forbidden_edge_ids`, `forbidden_action_types`, `mandatory_edge_ids`, `max_actions`, `cost_weight`.
- Mandatory fixes are currently chosen even if they exceed the budget or `max_actions`. This is a design choice awaiting team confirmation.
- A fix that increases the number of unknown paths is skipped.
- `recommend_fixes` raises `ValueError` if the assessments' `graph_version` does not match the snapshot.
- Each round scores a candidate as `gain - cost_weight * cost`. `cost_weight` defaults to `0.0`, so cost is ignored unless you set it.
- A mandatory edge with no matching candidate is reported in the result's assumptions, not dropped silently.
## Assumptions and limits

- A fix is "remove an edge". Simulation is edge removal on a graph copy, so real AWS policy semantics are not re-evaluated.
- Paths found on a forked graph must be scored against that fork.
## Scoring model (`scoring.py`)

`risk_score = likelihood x impact`, both on a 0-1 scale. It is a relative route score, not a probability.

**Impact** comes from the target's criticality via `RiskConfig.criticality_impact`: CRITICAL 1.0, HIGH 0.8, MEDIUM 0.5, LOW 0.2.

**Likelihood** starts from a length factor and is then multiplied per edge:
1. Length factor = `max(min_length_factor, 1 - per_hop_decay x (hops - 1))`, with `per_hop_decay = 0.15` and `min_length_factor = 0.2`.
2. Each edge multiplies by its status weight (`status_weight`): CONFIRMED 1.0, INFERRED 0.6, STALE 0.4.
3. Each edge that has conditions multiplies by `constrained_factor` (0.7).
4. The result is clamped to 0-1.

The 0.2 floor applies to the length factor only. The multipliers in steps 2 and 3 are applied afterwards, so a long path with weak edges can score below 0.2.

**Confidence** is separate from the score: `high` by default, `medium` if any edge is INFERRED or has conditions, `low` if any edge is STALE, and a CONDITIONAL path drops one level.

**Special cases**
- A BLOCKED path scores 0.0 with confidence `high`.
- A path is "unknown" (`risk_score = None`, confidence `unknown`, reasons in `unknowns`) if its graph version differs from the snapshot, its target is missing from the snapshot, or any edge is missing, `UNKNOWN`, or `INVALIDATED`.
- `rank_paths` sorts highest risk first. Unknown paths sort last and are never dropped.

All weights are configurable through `RiskConfig` and are assumptions that need team review.
## Run the tests

```powershell
python -m pytest backend/remediation -q
```

Tests are in `backend/remediation/tests/` and use simulated data only (no AWS).