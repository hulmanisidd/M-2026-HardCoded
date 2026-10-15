"""Raw scenario JSON -> P1 events -> P2 GraphUpdater -> repo.snapshot() -> P3 paths -> Neo4j

    $env:PYTHONPATH = "$PWD"
    $env:NEO4J_URI = "bolt://localhost:7687"; $env:NEO4J_USER = "neo4j"; $env:NEO4J_PASSWORD = "<pw>"
    python scripts/export_neo4j.py fixtures/organization/scenario_01_passrole_escalation.json
    python scripts/export_neo4j.py fixtures/organization/*.json            # all four, one graph
    python scripts/export_neo4j.py <scenario.json> --fail                  # edges go UNKNOWN
    python scripts/export_neo4j.py <scenario.json> --cypher-out out.cypher # no DB needed

Also writes P3 attack paths (scored by P4) as red-styleable :ATTACK_PATH relationships.
Wipes :Entity nodes first (same as load_seed_to_neo4j.py) unless --keep is given.
"""
import argparse
import glob
import json
import os
import re
import sys
from functools import partial
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.updater import GraphUpdater
from backend.ingestion.events import collection_failed_event, emit_collection_events
from backend.ingestion.snapshot import build_snapshot_from_file
from backend.paths import discover_paths
from backend.remediation.candidates import generate_candidates
from backend.remediation.optimizer import greedy_select
from backend.remediation.scoring import rank_paths
from backend.remediation.simulation import recommend
from backend.paths.engine import find_paths
from backend.rerouting.models import AccessRequirement, Outcome
from backend.rerouting.service import reroute
from contracts import Criticality, EdgeStatus, GraphSnapshot, PathOptions

ACCOUNT_ID = "111122223333"
T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
val = lambda x: getattr(x, "value", x)
ident = lambda s: re.sub(r"[^A-Za-z0-9_]", "_", str(s))


def cy(rows):
    """Rows as a Cypher list literal (bare map keys; values are valid Cypher via JSON)."""
    return "[" + ", ".join("{" + ", ".join(f"{k}: {json.dumps(v)}" for k, v in r.items()) + "}" for r in rows) + "]"


def build_snap(path, fail):
    src = build_snapshot_from_file(path, created_at=T0).snapshot
    events = list(emit_collection_events(src.entities, src.edges, account_id=ACCOUNT_ID, occurred_at=T0))
    if fail:
        events.append(collection_failed_event(account_id=ACCOUNT_ID, occurred_at=T0 + timedelta(minutes=5),
                                              reason="demo: simulated API failure"))
    now = T0 + timedelta(minutes=10 if fail else 0)
    repo = InMemoryGraphRepository(clock=lambda: now)
    updater = GraphUpdater(repo)
    for ev in events:
        updater.apply_event(ev)
    return repo.snapshot(), now, len(events)


ENTRY_TYPES = {"iam_user", "ec2_instance", "external_principal"}


def attack_path_rows(snap, scenario):
    """P3 paths + P4 scores -> one row per hop. Targets = holders of AdministratorAccess.

    Real P1 data has no criticality, so for SCORING ONLY those targets are treated as CRITICAL
    (otherwise P4 returns no score). The likelihood is P4's relative route score, not a probability.
    """
    entries = [n.entity_id for n in snap.entities if val(n.entity_type) in ENTRY_TYPES]
    admin = {n.entity_id for n in snap.entities if n.name == "AdministratorAccess"}
    targets = [e.source_id for e in snap.edges if e.target_id in admin and val(e.relation_type) == "has_policy"]
    res = discover_paths(snap, entries, targets, PathOptions(include_blocked=True))
    if not res.paths:
        return [], [], None
    ents = tuple(n.model_copy(update={"criticality": Criticality.CRITICAL}) if n.entity_id in targets else n
                 for n in snap.entities)
    scored = GraphSnapshot(version=snap.version, created_at=snap.created_at, entities=ents, edges=snap.edges)
    assess = {a.path_id: a for a in rank_paths(list(res.paths), scored)}
    name = {n.entity_id: n.name for n in snap.entities}
    ordered = sorted(res.paths, key=lambda p: (assess[p.path_id].risk_score is None,
                                               -(assess[p.path_id].risk_score or 0), p.path_id))
    rows = []
    for i, p in enumerate(ordered, 1):
        a = assess[p.path_id]
        lik = a.likelihood_score
        tag = f"Path {i}" + (f" | score {lik:.2f}" if lik is not None else " | score unknown")
        route = " -> ".join(name[n] for n in p.node_ids)
        for h, eid in enumerate(p.edge_ids):
            rows.append({"src": p.node_ids[h], "dst": p.node_ids[h + 1], "path_id": p.path_id,
                         "hop": h + 1, "hops": len(p.edge_ids), "via_edge_id": eid, "label": tag,
                         "route": route, "likelihood_score": lik, "risk_score": a.risk_score,
                         "confidence": a.confidence, "feasibility": val(p.feasibility_status),
                         "scenario": scenario})

    # --- P4 remediation: pick edges to cut, simulate on a forked copy, see what survives ---
    opts = PathOptions(include_blocked=True)
    find = lambda g: list(discover_paths(g, entries, targets, opts).paths)
    result = greedy_select(generate_candidates(list(res.paths), scored), scored, find)
    route_of = {r["path_id"]: r["route"] for r in rows}
    fixes = []
    for i, cand in enumerate(result.chosen, 1):
        rec = recommend(cand, scored, find)
        edge = scored.get_edge(cand.plan.removed_edge_ids[0])
        blocked = [route_of.get(pid, pid) for pid in rec.expected_blocked_path_ids]
        red = rec.estimated_risk_reduction
        fixes.append({"src": edge.source_id, "dst": edge.target_id, "fix_id": cand.candidate_id,
                      "label": f"Fix {i} | {cand.action_type.replace('_', ' ')}",
                      "action_type": cand.action_type, "cuts_edge": edge.edge_id,
                      "blocks_paths": len(blocked), "blocks": " ;; ".join(blocked),
                      "risk_reduction": red, "cost": cand.cost, "disruption": cand.disruption,
                      "paths_left_if_only_this": len(rec.residual_path_ids), "scenario": scenario})
    summary = {"cut_edge_ids": tuple(sorted({e for c in result.chosen for e in c.plan.removed_edge_ids})),
               "before": round(result.baseline.known_risk, 3), "after": round(result.residual.known_risk, 3),
               "paths_left": len(result.residual.residual_path_ids), "fixes": len(result.chosen)}
    return rows, fixes, summary


def reroute_rows(path, scenario, cut_edge_ids, access_file, assume_confirmed=True):
    """Legitimate access that the chosen fixes would break -> verified backup routes (P4 -> rerouting).

    The rerouting module fails closed: it will not verify a route made of INFERRED edges. Ingestion marks
    every policy-derived edge INFERRED, so by default this pass rebuilds the snapshot with those edges
    CONFIRMED (assume_confirmed=True: "the collected policies are authoritative"). Edge ids do not depend
    on status, so the optimizer's cut edges apply unchanged.
    """
    spec = json.load(open(access_file, encoding="utf-8"))
    status = EdgeStatus.CONFIRMED if assume_confirmed else EdgeStatus.INFERRED
    g = build_snapshot_from_file(path, created_at=T0, policy_edge_status=status).snapshot
    admin = admin_holders(g)
    ents = tuple(n.model_copy(update={"criticality": Criticality.CRITICAL}) if n.entity_id in admin else n
                 for n in g.entities)
    g = GraphSnapshot(version=g.version, created_at=g.created_at, entities=ents, edges=g.edges)
    by_name = {n.name: n.entity_id for n in g.entities if val(n.entity_type) != "iam_policy"}
    nm = {n.entity_id: n.name for n in g.entities}
    entries = tuple(n.entity_id for n in g.entities if val(n.entity_type) in ENTRY_TYPES)
    finder = partial(find_paths, entry_points=entries, targets=tuple(admin))
    complete = not discover_paths(g, entries, list(admin), PathOptions(include_blocked=True)).stats.truncated
    cut = [e for e in cut_edge_ids if g.get_edge(e) is not None]
    backups, lost, report_lines = [], [], []
    for r in spec["requirements"]:
        who, what = r["principal"], r["resource"]
        if who not in by_name or what not in by_name:
            report_lines.append(f"   access {who} -> {what}: skipped (name not found in scenario)")
            continue
        req = AccessRequirement(principal_id=by_name[who], resource_id=by_name[what],
                                trusted_entry_ids=tuple(by_name[t] for t in r.get("trusted", []) if t in by_name),
                                max_hops=r.get("max_hops", 4))
        rep = reroute(g, req, cut, find_attack_paths=finder, attack_search_complete=complete)
        report_lines.append(f"   access {who} -> {what}: {rep.outcome.value}"
                            + (" (route search truncated)" if rep.search_truncated else ""))
        if rep.outcome is Outcome.BACKUP_RECOMMENDED:
            b = rep.selected_backup
            route = " -> ".join(nm[n] for n in b.node_ids)
            sim = rep.simulation
            for h, eid in enumerate(b.edge_ids):
                backups.append({"src": b.node_ids[h], "dst": b.node_ids[h + 1], "route_id": b.path_id, "hop": h + 1,
                                "hops": b.hops, "via_edge_id": eid, "principal": who, "resource": what,
                                "label": f"Backup | {who} -> {what}" + (f" | hop {h + 1}/{b.hops}" if b.hops > 1 else ""),
                                "route": route, "replaces": " -> ".join(nm[n] for n in rep.primary.node_ids),
                                "simulated_safe": sim.is_safe, "scenario_risk_before": round(sim.known_risk_before, 3),
                                "scenario_risk_after": round(sim.known_risk_after, 3), "mode": rep.mode, "scenario": scenario})
        elif rep.outcome is Outcome.NO_VALID_BACKUP:
            n_alt = max(len(rep.assessments) - 1, 0)
            why = (f"primary route ({' -> '.join(nm[n] for n in rep.primary.node_ids)}) is cut by the fix; "
                   f"{n_alt} alternative route(s) examined, none passed every check")
            if rep.search_truncated:
                why += "; route search was depth-limited, so longer routes are not ruled out"
            lost.append({"src": by_name[who], "dst": by_name[what], "key": f"{who}>{what}",
                         "label": f"No verified backup | {who} -> {what}", "why": why,
                         "mode": rep.mode, "scenario": scenario})
    return backups, lost, report_lines


def admin_holders(snap):
    admin = {n.entity_id for n in snap.entities if n.name == "AdministratorAccess"}
    return {e.source_id for e in snap.edges if e.target_id in admin and val(e.relation_type) == "has_policy"}


def to_rows(snap, now, scenario, declutter=False):
    nodes = []
    for n in snap.entities:
        nodes.append({"id": n.entity_id, "name": n.name, "type": val(n.entity_type),
                      "criticality": val(n.criticality) if n.criticality else "unknown",
                      "account": n.account_id or "", "scenario": scenario})
    rels = defaultdict(list)
    holders = admin_holders(snap) if declutter else set()
    for e in snap.edges:
        # An admin holder can "modify" everything, which buries the real routes. Paths stop at the
        # first admin holder anyway, so these edges never appear on an attack path.
        if e.source_id in holders and val(e.relation_type) in ("can_assume", "can_pass_role", "can_modify_policy"):
            continue
        expired = bool(e.valid_until and e.valid_until <= now)
        rels[ident(val(e.relation_type)).upper()].append({
            "src": e.source_id, "dst": e.target_id, "edge_id": e.edge_id,
            "status": "expired" if expired else val(e.status),
            "conditions": json.dumps(e.conditions, default=str) if e.conditions else "",
            "valid_until": e.valid_until.isoformat() if e.valid_until else "",
            "scenario": scenario})
    return nodes, rels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenarios", nargs="+")
    ap.add_argument("--fail", action="store_true")
    ap.add_argument("--declutter", action="store_true", help="hide the admin roles' fan-out edges to every node")
    ap.add_argument("--strict-status", action="store_true",
                    help="rerouting: keep policy-derived edges INFERRED (module then verifies nothing)")
    ap.add_argument("--keep", action="store_true", help="don't wipe existing :Entity nodes first")
    ap.add_argument("--cypher-out")
    a = ap.parse_args()
    # PowerShell/cmd don't expand wildcards, so do it here
    paths = []
    for pat in a.scenarios:
        hits = sorted(glob.glob(pat))
        paths += hits if hits else [pat]
    a.scenarios = paths

    all_nodes, all_rels, all_paths, all_fixes = [], defaultdict(list), [], []
    all_backups, all_lost = [], []
    for path in a.scenarios:
        snap, now, n_events = build_snap(path, a.fail)
        scen = Path(path).stem
        nodes, rels = to_rows(snap, now, scen, a.declutter)
        all_nodes += nodes
        prow, frows, summ = attack_path_rows(snap, scen)
        all_paths += prow
        all_fixes += frows
        if summ:
            print(f"   fixes: {summ['fixes']} -> risk {summ['before']} -> {summ['after']}, "
                  f"{summ['paths_left']} path(s) left after all fixes")
            access_file = Path(path).parent / "access" / Path(path).name
            if access_file.exists() and summ["cut_edge_ids"]:
                bk, lost, lines = reroute_rows(path, scen, summ["cut_edge_ids"], access_file, not a.strict_status)
                all_backups += bk
                all_lost += lost
                print("\n".join(lines))
        print(f"   attack paths: {len({r['path_id'] for r in prow})}")
        for k, v in rels.items():
            all_rels[k] += v
        print(f"{scen}: {n_events} events -> {len(nodes)} nodes, {sum(map(len, rels.values()))} edges")

    # Same entity_id can appear in several scenarios (e.g. AdministratorAccess); keep one node, but
    # edge_ids hash source/type/target so identical edges merge too.
    uniq = {n["id"]: n for n in all_nodes}
    nodes = list(uniq.values())

    stmts = [("CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE", {})]
    by_type = defaultdict(list)
    for n in nodes:
        by_type[ident(n["type"])].append(n)
    for t, rows in by_type.items():          # labels can't be parameters, so one statement per type
        stmts.append((f"UNWIND $rows AS r MERGE (n:Entity {{id:r.id}}) SET n:{t}, n.name=r.name, n.type=r.type, "
                      f"n.criticality=r.criticality, n.account=r.account, n.scenario=r.scenario", {"rows": rows}))
    for rel, rows in all_rels.items():
        stmts.append((f"UNWIND $rows AS r MATCH (a:Entity {{id:r.src}}), (b:Entity {{id:r.dst}}) "
                      f"MERGE (a)-[x:{rel} {{edge_id:r.edge_id}}]->(b) "
                      f"SET x.status=r.status, x.conditions=r.conditions, x.valid_until=r.valid_until, "
                      f"x.scenario=r.scenario", {"rows": rows}))

    if all_paths:
        stmts.append(("UNWIND $rows AS r MATCH (a:Entity {id:r.src}), (b:Entity {id:r.dst}) "
                      "MERGE (a)-[x:ATTACK_PATH {path_id:r.path_id, hop:r.hop}]->(b) "
                      "SET x.label=r.label, x.hops=r.hops, x.via_edge_id=r.via_edge_id, x.route=r.route, "
                      "x.likelihood_score=r.likelihood_score, x.risk_score=r.risk_score, "
                      "x.confidence=r.confidence, x.feasibility=r.feasibility, x.scenario=r.scenario",
                      {"rows": all_paths}))

    if all_fixes:
        stmts.append(("UNWIND $rows AS r MATCH (a:Entity {id:r.src}), (b:Entity {id:r.dst}) "
                      "MERGE (a)-[x:FIX {fix_id:r.fix_id}]->(b) "
                      "SET x.label=r.label, x.action_type=r.action_type, x.cuts_edge=r.cuts_edge, "
                      "x.blocks_paths=r.blocks_paths, x.blocks=r.blocks, x.risk_reduction=r.risk_reduction, "
                      "x.cost=r.cost, x.disruption=r.disruption, x.paths_left_if_only_this=r.paths_left_if_only_this, "
                      "x.scenario=r.scenario", {"rows": all_fixes}))

    if all_backups:
        stmts.append(("UNWIND $rows AS r MATCH (a:Entity {id:r.src}), (b:Entity {id:r.dst}) "
                      "MERGE (a)-[x:BACKUP_ROUTE {route_id:r.route_id, hop:r.hop}]->(b) "
                      "SET x.label=r.label, x.hops=r.hops, x.via_edge_id=r.via_edge_id, x.principal=r.principal, "
                      "x.resource=r.resource, x.route=r.route, x.replaces=r.replaces, x.simulated_safe=r.simulated_safe, "
                      "x.scenario_risk_before=r.scenario_risk_before, x.scenario_risk_after=r.scenario_risk_after, x.mode=r.mode, x.scenario=r.scenario",
                      {"rows": all_backups}))
    if all_lost:
        stmts.append(("UNWIND $rows AS r MATCH (a:Entity {id:r.src}), (b:Entity {id:r.dst}) "
                      "MERGE (a)-[x:ACCESS_LOST {key:r.key}]->(b) "
                      "SET x.label=r.label, x.why=r.why, x.mode=r.mode, x.scenario=r.scenario",
                      {"rows": all_lost}))

    if a.cypher_out:
        with open(a.cypher_out, "w", encoding="utf-8") as f:
            if not a.keep:
                f.write("MATCH (n:Entity) DETACH DELETE n;\n")
            for q, p in stmts:
                rows = p.get("rows")
                f.write(q.replace("$rows", cy(rows) if rows is not None else "[]") + ";\n")
        print("wrote", a.cypher_out)

    if os.environ.get("NEO4J_PASSWORD"):
        from neo4j import GraphDatabase
        drv = GraphDatabase.driver(os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                                   auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]))
        with drv, drv.session() as s:
            if not a.keep:
                s.run("MATCH (n:Entity) DETACH DELETE n")
            for q, p in stmts:
                s.run(q, **p)
        print(f"Loaded {len(nodes)} nodes and {sum(map(len, all_rels.values()))} edges {len(all_paths)} attack-path hops and {len(all_fixes)} fixes, {len(all_backups)} backup-route hops and {len(all_lost)} lost-access markers into Neo4j.")
    elif not a.cypher_out:
        print("NEO4J_PASSWORD not set and no --cypher-out: nothing written.", file=sys.stderr)


if __name__ == "__main__":
    main()
