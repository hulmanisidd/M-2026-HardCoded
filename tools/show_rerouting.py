"""Show legitimate alternate routes (rerouting) on raw IAM data. Simulation only.

Usage:
  python tools/show_rerouting.py
  python tools/show_rerouting.py --cut analytics-gateway:reporting-reader
  python tools/show_rerouting.py --cut ana-analyst:analytics-gateway --cut ben-billing:billing-gateway
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.ingestion.snapshot import build_snapshot_from_file
from backend.paths.engine import find_paths
from backend.remediation.candidates import generate_candidates
from backend.remediation.optimizer import OptimizerConstraints, greedy_select
from backend.rerouting.config import ReroutingPolicy
from backend.rerouting.discovery import discover_access_paths
from backend.rerouting.models import AccessRequirement
from backend.rerouting.service import removed_edge_ids_of, reroute

DATA = ROOT / "fixtures" / "rerouting" / "scenario_08_access_rerouting.json"
ACCESS = ROOT / "fixtures" / "rerouting" / "access" / "scenario_08_access_rerouting.access.json"

ap = argparse.ArgumentParser()
ap.add_argument("--data", default=str(DATA))
ap.add_argument("--access", default=str(ACCESS))
ap.add_argument("--cut", action="append", default=[], help="extra what-if edge removal 'source:target' (entity names)")
args = ap.parse_args()

snap = build_snapshot_from_file(args.data, created_at=datetime(2026, 10, 15, tzinfo=timezone.utc)).snapshot
raw = json.load(open(args.data, encoding="utf-8"))
requirements = json.load(open(args.access, encoding="utf-8"))["requirements"]

name_of = {e.entity_id: e.name for e in snap.entities}


def ident(name):
    hits = [e.entity_id for e in snap.entities if e.name == name or e.entity_id == name
            or e.entity_id.endswith("/" + name)]
    if len(hits) != 1:
        sys.exit(f"cannot resolve '{name}' ({len(hits)} matches). entity names: {sorted(name_of.values())}")
    return hits[0]


def label(node_ids):
    return " -> ".join(name_of.get(n, n) for n in node_ids)


# entry points = every IAM user; targets = roles with AdministratorAccess (taken from the raw data)
entries = tuple(ident(u["UserName"]) for u in raw["UserDetailList"])
admins = tuple(ident(r["RoleName"]) for r in raw["RoleDetailList"]
               if any(m["PolicyName"] == "AdministratorAccess" for m in r["AttachedManagedPolicies"]))
finder = partial(find_paths, entry_points=entries, targets=admins)

# the plan: P4's own greedy fix, plus any what-if cuts from --cut
chosen = greedy_select(generate_candidates(finder(snap), snap), snap, finder, OptimizerConstraints()).chosen
removed = set(removed_edge_ids_of(chosen))
for spec in args.cut:
    s, t = (ident(x) for x in spec.split(":"))
    ids = [e.edge_id for e in snap.edges if e.source_id == s and e.target_id == t]
    if not ids:
        sys.exit(f"no edge {spec} in the graph")
    removed.update(ids)

print(f"graph {snap.version}: {len(snap.entities)} entities, {len(snap.edges)} edges")
print(f"attack paths found: {len(finder(snap))}")
print("edges removed by the plan:")
for e in snap.edges:
    if e.edge_id in removed:
        print(f"   x {name_of[e.source_id]} -> {name_of[e.target_id]}")

for req in requirements:
    # the requesting principal is the legitimate user, so its own entry is trusted for its own route
    r = AccessRequirement(principal_id=ident(req["principal"]), resource_id=ident(req["resource"]),
                          trusted_entry_ids=(ident(req["principal"]),))
    found = discover_access_paths(snap, r, ReroutingPolicy())
    print("\n" + "=" * 70)
    print(f"{req['principal']}  ->  {req['resource']}")
    print(f"legitimate routes discovered ({len(found.paths)}):")
    for p in found.paths:
        broken = any(e in removed for e in p.edge_ids)
        print(f"   {label(p.node_ids)}  [{p.hops} hops]{'  <- uses a removed edge' if broken else ''}")

    rep = reroute(snap, r, tuple(sorted(removed)), find_attack_paths=finder, attack_search_complete=True)
    print(f"outcome : {rep.outcome.value}   (mode: {rep.mode})")
    if rep.primary:
        print(f"primary : {label(rep.primary.node_ids)}")
    for a in rep.assessments:
        if rep.primary and a.path.path_id == rep.primary.path_id:
            continue
        tag = "SELECTED" if rep.selected_backup and a.path.path_id == rep.selected_backup.path_id else a.verdict.value.upper()
        print(f"   [{tag}] {label(a.path.node_ids)}")
        for b in a.blockers:
            print(f"        blocked: {b}")
    if rep.simulation:
        print(f"   switch simulation: safe={rep.simulation.is_safe}, access_preserved={rep.simulation.access_preserved}")
    for n in rep.notes:
        print(f"   - {n}")