"""Real pipeline -> map:  P1 events -> P2 GraphUpdater -> repo.snapshot() -> P3 paths -> graph_live.html

    $env:PYTHONPATH = "$PWD"
    python scripts/build_live_graph.py fixtures/organization/scenario_01_passrole_escalation.json
    python scripts/build_live_graph.py <scenario.json> --fail     # simulate a failed collection (edges go UNKNOWN)
    start graph_live.html
"""
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.updater import GraphUpdater
from backend.ingestion.events import collection_failed_event, emit_collection_events
from backend.ingestion.snapshot import build_snapshot_from_file
from backend.paths import discover_paths
from contracts import Criticality, PathOptions

ACCOUNT_ID = "111122223333"
T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
val = lambda x: getattr(x, "value", x)

ap = argparse.ArgumentParser()
ap.add_argument("scenario")
ap.add_argument("--fail", action="store_true", help="send COLLECTION_FAILED after the good collection")
ap.add_argument("--out", default="graph_live.html")
args = ap.parse_args()

# 1. P1: normalised input -> events
built = build_snapshot_from_file(args.scenario, created_at=T0)
src = built.snapshot
events = list(emit_collection_events(src.entities, src.edges, account_id=ACCOUNT_ID, occurred_at=T0))
if args.fail:
    events.append(collection_failed_event(account_id=ACCOUNT_ID, occurred_at=T0 + timedelta(minutes=5),
                                          reason="demo: simulated API failure"))

# 2. P2: events -> repository (same updater your tests use)
now = T0 + timedelta(minutes=10 if args.fail else 0)
repo = InMemoryGraphRepository(clock=lambda: now)
updater = GraphUpdater(repo)
for ev in events:
    updater.apply_event(ev)
snap = repo.snapshot()

# 3. P3: paths over the repository snapshot
# Entry points = identities an attacker could start as. Targets = critical/high entities, or (real
# P1 data carries no criticality yet) anything holding the AdministratorAccess policy.
ENTRY_TYPES = {"iam_user", "ec2_instance", "external_principal"}
entries = [n.entity_id for n in snap.entities if val(n.entity_type) in ENTRY_TYPES]
targets = [n.entity_id for n in snap.entities if n.criticality in (Criticality.CRITICAL, Criticality.HIGH)]
if not targets:
    admin = {n.entity_id for n in snap.entities if n.name == "AdministratorAccess"}
    targets = [e.source_id for e in snap.edges if e.target_id in admin and val(e.relation_type) == "has_policy"]
result = discover_paths(snap, entries, targets, PathOptions(include_blocked=True))

# 4. layout: BFS layers from the entry points, then export
ids = [n.entity_id for n in snap.entities]
depth = {i: 0 for i in ids}
seen = set(entries)
frontier = list(entries)
level = 0
while frontier:
    level += 1
    nxt = []
    for u in frontier:
        for e in snap.edges:
            if e.source_id == u and e.target_id not in seen:
                seen.add(e.target_id); depth[e.target_id] = level; nxt.append(e.target_id)
    frontier = nxt
cols, rows = {}, {}
for n in snap.entities:
    c = min(depth[n.entity_id], 6)
    rows[n.entity_id] = cols.get(c, 0)
    cols[c] = cols.get(c, 0) + 0.85
    depth[n.entity_id] = c

nodes = [{"key": n.entity_id, "id": n.entity_id, "name": n.name, "type": val(n.entity_type),
          "crit": val(n.criticality) if n.criticality else "unknown", "account": n.account_id,
          "col": depth[n.entity_id], "row": rows[n.entity_id]} for n in snap.entities]
ekey = {e.edge_id: f"E{i+1}" for i, e in enumerate(snap.edges)}
edges = []
for e in snap.edges:
    st = val(e.status)
    expired = bool(e.valid_until and e.valid_until <= now)
    visual = "expired" if expired else st if st in ("stale", "unknown", "invalidated") else ("conditional" if e.conditions else st)
    edges.append({"key": ekey[e.edge_id], "src": e.source_id, "dst": e.target_id, "rel": val(e.relation_type),
                  "status": st, "visual": visual, "conditions": e.conditions,
                  "valid_until": e.valid_until.isoformat() if e.valid_until else None})
paths = [{"edges": [ekey[i] for i in p.edge_ids], "feasibility": val(p.feasibility_status)} for p in result.paths]

data = {"nodes": nodes, "edges": edges, "paths": paths, "now": now.isoformat(),
        "version": snap.version[:12], "title": Path(args.scenario).stem}
html = Path(__file__).with_name("graph_template.html").read_text(encoding="utf-8")
Path(args.out).write_text(html.replace("/*DATA*/", json.dumps(data).replace("</", "<\\/")), encoding="utf-8")
print(f"{len(events)} events -> {len(nodes)} nodes, {len(edges)} edges, {len(paths)} paths -> {args.out}")
