# HardCoded demo runbook (Phase 1 smoke checklist)

Simulation only. Nothing here changes AWS. `/api/health` must report `applied_to_cloud: false`.

Environment: Windows / PowerShell, repo root `D:\ManipalMhash\HardCoded`, Python 3.13 venv `.venv`, Node v24 at `D:\`.

## 0. Setup (each new terminal)

```powershell
cd D:\ManipalMhash\HardCoded
.venv\Scripts\Activate.ps1
$env:Path += ";D:\"
```

## 1. Test baseline

```powershell
python -m pytest -q
```

Expected: all API tests pass (`tests/integration/test_api_health.py`, 4 tests) and **17 known failures**.

The 17 failures are all missing ground-truth files owned by Person 2:
`fixtures/expected_results/scenario_05..08*.edges.json`.
Do not create dummy files. Any failure outside that set is a regression.

## 2. Export check (no Neo4j credentials needed)

Run the exporter with `--cypher-out` first. Until exporters are consolidated, use `export_neo4j_green.py`
(only it writes `:FIX`, `:BACKUP_ROUTE`, `:ACCESS_LOST`; `export_neo4j.py` writes `:ATTACK_PATH` only).

```powershell
python export_neo4j_green.py fixtures/organization/scenario_08_access_rerouting.json --cypher-out out_s08.cypher
python export_neo4j_green.py fixtures/organization/scenario_06_privesc_toolkit.json --cypher-out out_s06.cypher
```

Record in the demo notes:
- [ ] Printed fix summary (`fixes: N -> risk A -> B, K path(s) left`)
- [ ] Printed rerouting lines, or a visible warning
- [ ] Relationship-type counts, if printed
- [ ] Does `out_s08.cypher` contain `BACKUP_ROUTE`? (PowerShell: `Select-String BACKUP_ROUTE out_s08.cypher`)

Known issue (Person 1): the exporter builds the sidecar path as `access/<scenario>.json`, but the real file is
`access/<scenario>.access.json`. Until fixed, scenario 08 skips rerouting silently. If there is no
`BACKUP_ROUTE` and no warning, this is the cause, not styling.

Optional, with Neo4j running and server-side credentials set, in Neo4j Browser:

```cypher
MATCH (n:Entity) RETURN count(n) AS entities;
MATCH ()-[r]->() RETURN type(r) AS relationship_type, count(*) AS count ORDER BY count DESC;
MATCH (a:Entity)-[r:BACKUP_ROUTE]->(b:Entity) RETURN a, r, b;
```

Zero `BACKUP_ROUTE` rows means the problem is upstream (sidecar lookup, route selection or export), not arrow color.

## 3. API status

Terminal A:

```powershell
python -m uvicorn backend.api.main:app --reload --port 8000
```

Terminal B (a second PowerShell, after section 0):

```powershell
Invoke-RestMethod http://localhost:8000/api/health
Invoke-RestMethod http://localhost:8000/api/scenarios
Invoke-RestMethod http://localhost:8000/api/scenarios/scenario_06_privesc_toolkit/paths | ConvertTo-Json -Depth 4 | Select-Object -First 40
```

Check:
- [ ] `/api/health` returns `applied_to_cloud: false`
- [ ] `/api/scenarios` lists all 8 scenarios
- [ ] `/paths` returns paths with `feasibility` values (`feasible_under_model`, `conditional`, `blocked`)
- [ ] A truncated search is reported as truncated, never as complete
- [ ] An unknown scenario id returns a clean 404, not a stack trace

Note: all paths currently show `conditional`, because ingestion marks policy edges `inferred` and the transition
check downgrades any non-confirmed edge. This is expected until Persons 1 and 2 change it. The demo needs some
`feasible_under_model` paths.

## 4. UI check

```powershell
cd frontend
npm run dev
```

Open http://localhost:5173, select a scenario, then check:
- [ ] Whole map renders; layer chips (Attack paths / Fixes / Backup routes) do not move nodes
- [ ] Simulation-only banner is visible
- [ ] Truncation banner appears when the API reports truncation
- [ ] Inspector shows status, conditions and evidence for a clicked node or edge
- [ ] Fixes / Backup show "soon" until `/overlays` exists

### Expected UI when no valid backup route exists

For a scenario where rerouting returns `NO_VALID_BACKUP` (or the search is truncated, or conditions are unknown):
- [ ] No green `BACKUP_ROUTE` edge is drawn
- [ ] An amber `ACCESS_LOST` panel or marker explains which legitimate access would be lost
- [ ] The reason is visible: no qualifying route, truncated search, or unknown conditions
- [ ] The UI never shows `BACKUP_RECOMMENDED` for a truncated search (fail closed)
- [ ] ATTACK_PATH, FIX and BACKUP_ROUTE stay visually and conceptually separate

## 5. Overlays, simulation and pipeline (API)

With the API running (section 3), in PowerShell:

```powershell
$u = "http://localhost:8000/api/scenarios/scenario_08_access_rerouting"
Invoke-RestMethod "$u/overlays" | ConvertTo-Json -Depth 6
Invoke-RestMethod "$u/pipeline" | ConvertTo-Json -Depth 6
Invoke-RestMethod "$u/recommendations" | ConvertTo-Json -Depth 6
Invoke-RestMethod "$u/access-requirements" | ConvertTo-Json -Depth 6
$r = Invoke-RestMethod -Method Post -ContentType 'application/json' -Body '{"fix_ids": null}' "$u/simulate-remediation"
Invoke-RestMethod "http://localhost:8000/api/runs/$($r.run_id)" | ConvertTo-Json -Depth 3
```

Expected for scenario 08 (all fixes): 3 fixes, 7 paths before, 7 removed, 0 residual, `ana-analyst -> reporting-reader`
preserved via `reports-gateway`, `ben-billing -> billing-ledger` lost (no verified backup).

Check:
- [ ] Every response says `applied_to_cloud: false` / `SIMULATION_ONLY`, and recommendations have `requires_human_approval: true`
- [ ] A truncated search shows `residual_is_lower_bound: true` and no verified backup routes (fail closed)
- [ ] `/api/runs/<id>` returns the run; an unknown id returns 404 (runs are in memory and lost on restart)
- [ ] Pipeline stages: fixture, entities, relationships, paths, risk, fix, residual; `neo4j.configured` is false

## 6. UI acceptance (scenario_08_access_rerouting)

- [ ] Layer chips show counts (7 / 3 / 1) on one line each; if the overlays endpoint is down they show `n/a`, not `soon`
- [ ] Backup layer shows the green route and the amber `ben-billing -> billing-ledger` access-lost card with its reason
- [ ] Fixes layer: "Simulate all fixes" shows the approval banner (human approval required, nothing applied to AWS), 7 removed, 0 residual, access preserved and lost
- [ ] One fix selected: "Simulate this fix" shows 2 removed and 5 still reachable
- [ ] Search box dims non-matching nodes; Enter selects the first match
- [ ] Filters: node type, relation, path feasibility; "hide admin fan-out" never hides an edge that belongs to a layer
- [ ] Pipeline button opens the stage timeline and the "what Neo4j is doing" pane
- [ ] Stop the API: the page shows "Can't reach the API" with a working Retry button
- [ ] Header shows `neo4j: not configured`; the browser never holds database credentials
- [ ] Hovering a node dims others without piling up edge labels

## 7. Sign-off

| Check | Result | Notes |
|---|---|---|
| pytest: 17 known failures only | | |
| Exporter summary captured | | |
| `BACKUP_ROUTE` in scenario 08 output (needs Person 1's sidecar fix) | | |
| `/api/health` `applied_to_cloud: false` | | |
| Overlays / simulate / pipeline checks (section 5) | | |
| UI acceptance (section 6) | | |
| No-valid-backup state shows reason | | |

Known open items owned by others: the exporter sidecar filename (Person 1), rerouting returning `BACKUP_RECOMMENDED`
on a truncated search (Person 2), missing `scenario_05..08*.edges.json` (Person 2), all paths showing `conditional`,
owner/approver and NHI context fields (Person 1), `backend/updates/` wiring (not started).
