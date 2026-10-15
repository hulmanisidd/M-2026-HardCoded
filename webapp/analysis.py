"""Pipeline as an importable function.

This is the body of build_live_graph.py (steps 1-4) with the argparse / HTML writing removed.
Behaviour is kept identical, including the fixed T0 and ACCOUNT_ID so output is reproducible.
"""
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
ENTRY_TYPES = {"iam_user", "ec2_instance", "external_principal"}


def _val(x):
    return getattr(x, "value", x)


def build_graph_data(scenario_path, fail=False) -> dict:
    scenario_path = Path(scenario_path)

    # 1. normalised input -> events
    built = build_snapshot_from_file(str(scenario_path), created_at=T0)
    src = built.snapshot
    events = list(emit_collection_events(src.entities, src.edges, account_id=ACCOUNT_ID, occurred_at=T0))
    if fail:
        events.append(collection_failed_event(account_id=ACCOUNT_ID, occurred_at=T0 + timedelta(minutes=5),
                                              reason="demo: simulated API failure"))

    # 2. events -> repository
    now = T0 + timedelta(minutes=10 if fail else 0)
    repo = InMemoryGraphRepository(clock=lambda: now)
    updater = GraphUpdater(repo)
    for ev in events:
        updater.apply_event(ev)
    snap = repo.snapshot()

    # 3. paths
    entries = [n.entity_id for n in snap.entities if _val(n.entity_type) in ENTRY_TYPES]
    targets = [n.entity_id for n in snap.entities if n.criticality in (Criticality.CRITICAL, Criticality.HIGH)]
    if not targets:
        admin = {n.entity_id for n in snap.entities if n.name == "AdministratorAccess"}
        targets = [e.source_id for e in snap.edges if e.target_id in admin and _val(e.relation_type) == "has_policy"]
    result = discover_paths(snap, entries, targets, PathOptions(include_blocked=True))

    # 4. layout: BFS layers from the entry points
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
                    seen.add(e.target_id)
                    depth[e.target_id] = level
                    nxt.append(e.target_id)
        frontier = nxt
    cols, rows = {}, {}
    for n in snap.entities:
        c = min(depth[n.entity_id], 6)
        rows[n.entity_id] = cols.get(c, 0)
        cols[c] = cols.get(c, 0) + 0.85
        depth[n.entity_id] = c

    nodes = [{"key": n.entity_id, "id": n.entity_id, "name": n.name, "type": _val(n.entity_type),
              "crit": _val(n.criticality) if n.criticality else "unknown", "account": n.account_id,
              "col": depth[n.entity_id], "row": rows[n.entity_id]} for n in snap.entities]
    ekey = {e.edge_id: f"E{i+1}" for i, e in enumerate(snap.edges)}
    edges = []
    for e in snap.edges:
        st = _val(e.status)
        expired = bool(e.valid_until and e.valid_until <= now)
        visual = "expired" if expired else st if st in ("stale", "unknown", "invalidated") else ("conditional" if e.conditions else st)
        edges.append({"key": ekey[e.edge_id], "src": e.source_id, "dst": e.target_id, "rel": _val(e.relation_type),
                      "status": st, "visual": visual, "conditions": e.conditions,
                      "valid_until": e.valid_until.isoformat() if e.valid_until else None})
    paths = [{"edges": [ekey[i] for i in p.edge_ids], "feasibility": _val(p.feasibility_status)} for p in result.paths]

    return {"nodes": nodes, "edges": edges, "paths": paths, "now": now.isoformat(),
            "version": snap.version[:12], "title": scenario_path.stem}
