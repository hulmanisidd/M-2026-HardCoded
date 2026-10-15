# P5 — Continuous Update and Verification Engine

Public entry point: `UpdateEngine` (`engine.py`). Everything outside P5 is injected, so it runs on mocks.

```python
engine = UpdateEngine(repo=repo, entry_points=[...], targets=[...],
                      risk_ranker=rank_paths,            # P4 (optional)
                      inventory_provider=collect,        # P1 authoritative refresh (optional)
                      event_applier=apply_event)         # P2 apply_event (optional)
engine.start()                                           # initial discovery + risk
repo = engine.watched_repo                               # P2 writes through this reach P5 automatically
engine.handle_change(change)      -> UpdateResult        # P2 notification
engine.handle_event(event)        -> EventOutcome        # P1 NormalizedEvent
engine.reconcile()                -> ReconciliationResult
engine.register_recommendation(rec, plan)                # from P4
engine.verify_remediation(rec_id) -> VerificationReport
engine.system_status()            -> SystemStatus        # for the future API / dashboard
```

| File | Job |
|---|---|
| `coordinator.py` | Keeps the path index current. Strategy per change: `skipped` / `incremental` / `full`. |
| `dependencies.py` | edge→paths and node→paths index. |
| `versioning.py` | `EpochGuard`: an older computation can never overwrite a newer result. |
| `events.py` | P1 event intake (dedupe, retry), P2 change forwarding, reference event applier. |
| `reconciliation.py` | Compare authoritative inventory with the graph; repair only through P2. |
| `scheduler.py` | Periodic reconciliation (`tick(now)` is deterministic; `start_background` for real use). |
| `status.py` | Source freshness (FRESH/STALE/FAILED/UNKNOWN) and the system status summary. |
| `verification.py` | Verdict: VERIFIED / PARTIALLY_VERIFIED / SIMULATED / FAILED / UNKNOWN. |
| `engine.py` | Wires it all together; contract methods. |

## Rules this module enforces
* **VERIFIED needs authoritative, fresh, complete source evidence** and a complete path search. Stale or partial source → `PARTIALLY_VERIFIED`; unreachable → `UNKNOWN`; no source → `SIMULATED`.
* A source that still shows the planned edge live → `FAILED` (not `UNKNOWN`).
* A partial inventory never claims "in sync" and never invalidates edges (absence ≠ proof).
* Edges missing from the source are **invalidated, never deleted**. P2 has no entity removal, so extra entities are reported, not removed.
* Alternate routes stay visible after a fix (`alternate_routes_remain`, `residual_assessments`).
* Every path / risk result carries the graph version it was computed on.

## Recompute strategy (always equal to a from-scratch P3 run)
* `skipped`: change provably cannot touch any entry→target route (isolated entity, dead-end edge).
* `incremental`: an edge used by known paths was invalidated → exactly those paths are dropped.
* `full`: anything that could add/alter routes, or when incremental is unsafe: earlier search truncated, `include_blocked`, missed/out-of-order/concurrent updates, or edge validity windows crossed by time.

## Known limits (documented, not hidden)
* Graph versions are content hashes, so ordering comes from per-computation epochs, not version comparison.
* Out-of-order notifications are handled by resyncing, not by re-ordering them.
* `EdgeInvalidationApplier` is a reference mock until P2 ships `apply_event`.
* Reconciliation compares entities/edges field-by-field (ignoring `observed_at`); it does not evaluate IAM semantics.
