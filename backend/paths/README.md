# Attack Path Discovery (P3)

## Purpose

P3 discovers bounded attack paths through a read-only graph snapshot. It evaluates edge transitions, classifies path feasibility, and reports search statistics for downstream consumers.

## Public API

Import the public functions from `backend.paths`:

- `discover_paths(snapshot, entry_points, targets, options=None)` returns a `PathSearchResult` containing paths, graph version, and search statistics.
- `find_paths(snapshot, entry_points, targets, options=None)` returns a list of `AttackPath`. Use this when statistics are not needed.
- `paths_using_edge(paths, edge_id)` returns the paths containing the specified edge. P5 can use this to identify affected paths after an edge change.

Prefer `discover_paths` when truncation, blocked transitions, or unknown entry/target IDs must be reported.

## Inputs

- **Snapshot:** A read-only graph reader implementing `version`, `get_neighbors(entity_id)`, and `check_transition(edge_id, context)`.
- **Entry points:** Entity IDs from which traversal starts.
- **Targets:** Entity IDs that terminate a discovered path.
- **PathOptions:** Configurable traversal limits and relation filters.

The reader should expose `entities` for unknown-ID detection. If it does not, unknown entry and target IDs cannot be verified and are not reported as unknown.

## Outputs

`PathSearchResult` includes:

- `graph_version`: version of the graph used for discovery.
- `paths`: discovered `AttackPath` objects.
- `stats`: search statistics, including paths found, blocked transitions rejected, unknown entry/target IDs, and truncation information.

Each attack path records its path ID, graph version, entry and target IDs, node and edge sequences, feasibility status, evidence IDs, and explanations.

## Behavior and assumptions

- `MEMBER_OF` and `HAS_POLICY` relations are excluded from the default attack-step relation set. Callers can override this through `PathOptions.allowed_relation_types`.
- Traversal enumerates bounded simple paths; a path does not repeat a node.
- `max_paths` is a total cap across entry points. Reaching the cap is reported conservatively as truncation.
- `path_id` is derived from edge IDs and does not include the graph version. Use `(path_id, graph_version)` when identifying a path within a specific snapshot.
- Unknown entry and target IDs are reported only when the reader exposes its entities.
- Transition statuses are evaluated by the graph reader. Blocked transitions are excluded by default; `include_blocked` can request blocked paths where supported.
- The implementation uses custom bounded traversal, not NetworkX.

## Tests

From the repository root, run the P3 unit tests:

```powershell
python -m pytest tests/unit/test_paths_engine.py tests/unit/test_paths_ground_truth.py tests/unit/test_paths_traversal.py tests/unit/test_paths_validator.py -q
```

Run the complete test suite with:

```powershell
python -m pytest -q
```
