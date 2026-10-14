# AWS IAM Attack-Path Graph Backend

In-memory, versioned graph of AWS IAM entities and relationships, with
event-time freshness tracking. Downstream components (path search, scoring,
remediation) read immutable `GraphSnapshot`s; the updater writes through
`GraphRepository`.

## Running the tests

```powershell
python -m pytest -q
```

`pytest.ini` sets `--import-mode=importlib` so test files with the same
basename in different folders do not collide.

## Inputs

| Input | Source | Notes |
|---|---|---|
| `Entity` | updater / seed data | Node: user, role, group, policy, etc. |
| `Relationship` | updater / seed data | Directed edge with a `status`. |
| `observed_at` | updater | When the source data was observed (event time, UTC, timezone-aware). |
| `source_api` | updater | The API call that produced the edge, e.g. `iam:GetAccountAuthorizationDetails`. |
| `Scope` | updater | `(account_id, source_api)`. Reported when a collection fails. |

The updater always supplies `observed_at` and `source_api` for observed edges.
Seed and direct writes may omit them.

## Outputs

- `GraphChange` returned from every write: `kind`, `subject_id`, `changed`
  (False if the write was ignored or a no-op), and the graph `version`.
- `GraphSnapshot` from `snapshot()`: immutable, with `version`, `created_at`,
  entities, and edges with staleness already applied.

## Edge status meanings

| Status | Meaning |
|---|---|
| `confirmed` | Directly observed and still within the freshness window. |
| `inferred` | Derived by reasoning (e.g. from a policy), not observed directly. |
| `stale` | Was `confirmed`/`inferred`, but `observed_at + freshness_window` has passed. Computed at read time. |
| `unknown` | The collection that would have refreshed this edge failed. We cannot say whether it exists. |
| `invalidated` | Known to no longer exist. |

## Behaviour rules

1. **Staleness is computed, not stored.** `get_edge` returns the stored status;
   `snapshot()` applies `STALE` as of the snapshot clock. An edge turns stale
   exactly at `observed_at + window` (`>=`).
2. **Only `confirmed` and `inferred` edges can go stale.** `unknown` and
   `invalidated` are never overridden.
3. **No `observed_at` means never judged.** Such edges are never stale and are
   never marked unknown by a collection failure.
4. **Strictly newer wins; ties go to the first event.** A write whose event
   time is `<=` the latest recorded observation, invalidation, or unknown
   marking for that edge is ignored (`changed=False`).
5. **Invalidated stays invalidated** unless the write carries an `observed_at`
   newer than the invalidation (a fresh re-grant) or `reinstate=True`.
6. **Scope unknown.** `mark_scope_unknown(scope, at=...)` marks every held,
   observed, non-invalidated edge whose `source_api` matches and whose source
   entity's `account_id` matches as `UNKNOWN`. A report older than an edge's
   latest event is ignored for that edge.
7. **Only a newer observation clears `UNKNOWN`.** A write with no `observed_at`
   cannot overwrite an `UNKNOWN` edge.
8. **Version stability.** The version hash covers entities, effective edges
   (after staleness) and time-blocked edge ids, not raw timestamps. Same
   content and same effective state gives the same version, until a validity
   window or freshness boundary is crossed.
9. **Freshness window.** `DEFAULT_FRESHNESS_WINDOW = 24h` is a **placeholder**.
   Pass `freshness_window=None` to disable staleness.

## Public interface (Milestone 1)

### `InMemoryGraphRepository(clock=_utc_now, freshness_window=24h)`

| Method | Returns | Description |
|---|---|---|
| `upsert_entity(entity, *, observed_at=None)` | `GraphChange` | Add or update a node. Older `observed_at` is ignored. |
| `upsert_edge(edge, *, reinstate=False, observed_at=None, source_api=None)` | `GraphChange` | Add or update an edge. Raises `ValueError` if an endpoint entity is unknown. |
| `invalidate_edge(edge_id, *, at=None)` | `GraphChange` | Mark an edge invalidated. Raises `KeyError` if unknown. Stale removals are ignored. |
| `mark_scope_unknown(scope, *, at)` | `GraphChange` | Summary change of kind `SCOPE_MARKED_UNKNOWN`; `subject_id` is `scope.key`. |
| `get_entity(entity_id)` | `Entity \| None` | Raw read. |
| `get_edge(edge_id)` | `Relationship \| None` | Raw read, no staleness applied. |
| `get_neighbors(entity_id)` | `list[Relationship]` | Outgoing edges, sorted by `edge_id`. |
| `snapshot()` | `GraphSnapshot` | Immutable view with staleness applied; `version` and `created_at` use one clock read. |

`ChangeKind`: `ENTITY_ADDED`, `ENTITY_UPDATED`, `EDGE_ADDED`, `EDGE_UPDATED`,
`EDGE_INVALIDATED`, `SCOPE_MARKED_UNKNOWN`, `COLLECTION_COMPLETED`.

### `GraphUpdater(repo: GraphRepository)`

Turns P1's `NormalizedEvent`s into repository writes. One entry point:
`apply_event(event: NormalizedEvent) -> GraphChange`.

`event.occurred_at` is the observation time. Delivery is at-least-once and
unordered; the repository ignores anything not strictly newer than what it
holds, so order does not matter.

| `event_type` | Payload | Effect |
|---|---|---|
| `ENTITY_UPSERTED` | `entity: dict` | `upsert_entity(observed_at=occurred_at)`. A null `criticality` is dropped so the default (`LOW`) applies. |
| `ENTITY_REMOVED` | `entity_id: str` | No-op (`changed=False`). Entities are never deleted and incident edges are not invalidated, pending P1's confirmation. |
| `EDGE_OBSERVED` | `edge: dict` | Only `confirmed`/`inferred` accepted. `edge_id` is recomputed and must match. Both endpoints must exist. Calls `upsert_edge(observed_at=occurred_at, source_api=event.source)`. |
| `EDGE_REMOVED` | `edge_id`, `source_id`, `target_id`, `relation_type`, optional `discriminator` | `invalidate_edge(at=occurred_at)`. If the edge has not arrived yet, an `INVALIDATED` tombstone is stored so the older observation is ignored when it shows up. |
| `COLLECTION_COMPLETED` | `scope: {account_id, source_api}` | No-op, kind `COLLECTION_COMPLETED`. `UNKNOWN` edges clear only when re-emitted as `EDGE_OBSERVED` with a newer time. |
| `COLLECTION_FAILED` | `scope: {account_id, source_api}` | `mark_scope_unknown(scope, at=occurred_at)`. |

Errors:

- `RejectedEvent` (a `ValueError`): the event is malformed or breaks the
  agreed rules. Do not retry.
- `MissingEndpointError` (a `RejectedEvent`): an endpoint entity has not
  arrived yet. Requeue and retry.

Contract with P1: `event.source` on `EDGE_OBSERVED` must equal
`scope.source_api` on `COLLECTION_FAILED` for the same API. Scope matching
compares these strings exactly, so a mismatch means a failed collection marks
nothing `UNKNOWN`.

### Change listeners (optional, for P5)

`repo.subscribe(callback)` registers `callback(change: GraphChange)`, called
only when `change.changed` is true.

## Seed data

`backend/graph/seed_data.py` builds a synthetic org (11 entities, 13 edges)
with a hand-written `EXPECTED_PATHS` fixture of 15 paths: 13 non-blocked and
2 blocked. Example: `alice -> dev-role -> ops-role -> etl-role ->
customer-data`. Edge `E11` is expired and `E2` is stale. `E10` is unknown and
`E9` carries unresolved conditions.

Expiry is judged against `snapshot.created_at`, so build the repository with
`clock=lambda: SEED_NOW`. `load_into(repo)` writes without `observed_at`, so
seed edges are never judged stale or marked unknown by the freshness rules.

## Known gaps

- `observed_at` is not a field on `Relationship`; the repository keeps its own
  event-time ledger (`_observed_at`, `_invalidated_at`, `_unknown_since`).
- `EventType` enum not yet in the contracts (`NormalizedEvent.event_type` is a
  plain `str`).
- `Entity.criticality` defaults to `LOW`; the agreed `Criticality | None` is
  not implemented.
- `ENTITY_REMOVED` is not handled, pending P1's confirmation.
- The freshness window needs a team decision.