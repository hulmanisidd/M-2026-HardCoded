# Rerouting (backup legitimate access paths)

Given a set of edges that will be removed or are unavailable, this module answers:
**can the legitimate principal still reach the resource, and is there a verified, safe alternative route?**

It is a **simulation and recommendation** module. It never changes real AWS permissions or routing.

## Two concepts, kept apart

| Concept | Handled by | What happens |
|---|---|---|
| Attack paths (dangerous routes) | P3 discovery, P4 simulation and optimizer | Detected and eliminated or mitigated. Never used as backups. |
| Legitimate access paths | This module | Primary identified, backups discovered, validated, simulated, ranked. |

## Pipeline

```python
from functools import partial
from backend.paths.engine import find_paths
from backend.remediation.candidates import generate_candidates
from backend.remediation.optimizer import OptimizerConstraints, greedy_select
from backend.rerouting.models import AccessRequirement
from backend.rerouting.service import removed_edge_ids_of, reroute

finder = partial(find_paths, entry_points=("attacker",), targets=("bucket",))
chosen = greedy_select(generate_candidates(finder(g), g), g, finder, constraints).chosen

req = AccessRequirement(principal_id="dev", resource_id="bucket")
report = reroute(g, req, removed_edge_ids_of(chosen),
                 find_attack_paths=finder, attack_search_complete=True)

# Feed the result back so P4 will not cut the recommended backup:
constraints = OptimizerConstraints(forbidden_edge_ids=frozenset(report.protected_edge_ids))
```

`attack_search_complete` has no default. The caller must state whether the attack-path
search was NOT truncated, because P4 cannot detect that itself.

## Flow inside `reroute()`

1. Discover legitimate routes (`discovery.py`).
2. Build the post-change view with P4's `simulate_plan` and `residual_risk` (`simulation.py`).
3. Identify the primary route (`selector.py`, or `AccessRequirement.primary_edge_ids` if known).
4. If the primary still passes every check, return `PRIMARY_STILL_VALID`.
5. Otherwise validate every other route (`validators.py`, fail-closed).
6. Simulate the switch for each fully verified route, shortest first. The first safe one wins.
7. If none qualifies, return `NO_VALID_BACKUP` with the reason for each rejected route.

## Outcomes

| Outcome | Meaning |
|---|---|
| `PRIMARY_STILL_VALID` | The change does not break or expose the primary. No rerouting needed. |
| `BACKUP_RECOMMENDED` | A verified backup exists and its simulated switch is safe. |
| `NO_VALID_BACKUP` | No alternative passed every check. Reported honestly, with reasons in `notes`. |
| `PRIMARY_UNVERIFIABLE` | The primary cannot be confirmed, so nothing is guessed. |

## Fail-closed rules

- A missing check is UNKNOWN. Only all-VERIFIED routes qualify.
- A VERIFIED verdict without evidence is rejected.
- Edges that are stale, lack `evidence_ids`, or carry conditions with no evaluator are not trusted.
- Privilege-escalation relations are never treated as legitimate routes.
- A backup reachable from an untrusted entry point is rejected (`trusted_entry_ids` can whitelist entries).
- An unavailable edge (`unavailable_edge_ids`) is never recommended.
- Truncated route search or incomplete attack search never produces a recommendation. Absence of a route is reported as "not proven".

## Implemented vs simulated vs absent

| Item | Status |
|---|---|
| Route discovery, fail-closed validation, ranking, report | Implemented |
| Switch simulation (edge removal on a graph copy, via P4) | Simulated |
| Availability from the graph and reported outages | Simulated |
| `protected_edge_ids` fed back to P4 as `forbidden_edge_ids` | Implemented |
| Live health checks | Not implemented |
| Real IAM condition evaluation (`ConditionEvaluator` port) | Not implemented. Conditions stay UNKNOWN. |
| Changing real AWS permissions or routing | Absent on purpose |

The report `mode` is `simulated_recommendation_only`. A test checks that the module imports no
AWS or network libraries.

## Assumptions

- Without `primary_edge_ids`, the primary is assumed: the verified route that the change breaks or
  exposes, otherwise the shortest verified route. This can recommend an unnecessary backup but
  cannot miss a needed one.
- Simulation does not re-evaluate real AWS policy semantics.
- Shortest verified route is preferred because fewer hops means fewer things to break.

## Tests

```
python -m pytest tests/unit/test_rerouting_models.py tests/unit/test_rerouting_discovery.py tests/unit/test_rerouting_validators.py tests/unit/test_rerouting_service.py tests/integration/test_rerouting_pipeline.py -q
```

## Team to confirm

1. Whether usage data (for example CloudTrail) is available to supply `primary_edge_ids`.
2. Who supplies a `ConditionEvaluator` for IAM conditions.
3. Whether anything beyond recommendation is wanted. A deployment mechanism needs explicit approval.
4. Which entry points count as trusted (`trusted_entry_ids`).
5. Who owns telling `reroute()` that the attack-path search was complete.