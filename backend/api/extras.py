"""Read-only extras: pipeline summary, recommendations, access requirements. Simulation only."""
import json
from collections import Counter

from . import overlays, service

val = service.val


def pipeline(scenario_id: str) -> dict:
    fixture = service._fixture(scenario_id)
    built = service._build(scenario_id)
    snap = built.snapshot
    p = service.paths(scenario_id)
    ov = overlays.overlays(scenario_id)
    status = Counter(val(e.status) for e in snap.edges)
    rel = Counter(str(val(e.relation_type)).upper() for e in snap.edges)
    types = Counter(val(n.entity_type) for n in snap.entities)
    feas = Counter(x["feasibility"] for x in p["paths"])
    summ = ov["summary"]
    hops = sum(len(x["edge_ids"]) for x in p["paths"])
    backup_edges = sum(len(b["edge_ids"]) for b in ov["backup_routes"])
    inferred = status.get("inferred", 0)

    def fmt(c):
        return ", ".join(f"{k} {v}" for k, v in sorted(c.items())) or "none"

    path_warn = []
    if p["search"]["truncated"]:
        path_warn.append(f"Search truncated: {p['search']['truncation_reason']}")
    rel_warn = [f"{inferred} edge(s) are inferred from policy text, not confirmed; "
                "paths using them stay conditional."] if inferred else []
    stages = [
        {"key": "fixture", "label": "Fixture", "count": 1, "unit": "scenario file",
         "detail": f"{fixture.name} (synthetic)", "warnings": list(built.warnings)},
        {"key": "entities", "label": "Entities", "count": len(snap.entities), "unit": "nodes",
         "detail": fmt(types), "warnings": []},
        {"key": "relationships", "label": "Relationships", "count": len(snap.edges), "unit": "edges",
         "detail": "status: " + fmt(status), "warnings": rel_warn},
        {"key": "paths", "label": "Attack paths", "count": p["search"]["paths_found"], "unit": "paths",
         "detail": "feasibility: " + fmt(feas), "warnings": path_warn},
        {"key": "risk", "label": "Risk", "count": summ["risk_before"] if summ else None,
         "unit": "relative score", "detail": "Relative route score, not a probability.", "warnings": []},
        {"key": "fix", "label": "Fixes", "count": len(ov["fixes"]), "unit": "proposed",
         "detail": (f"risk after all fixes: {summ['risk_after']}" if summ else "no fixes proposed"),
         "warnings": list(ov["warnings"])},
        {"key": "residual", "label": "Residual / backup",
         "count": summ["paths_left"] if summ else None, "unit": "paths left",
         "detail": f"{len(ov['backup_routes'])} backup route(s), {len(ov['access_lost'])} access lost",
         "warnings": []},
    ]
    return {
        "scenario_id": scenario_id, "graph_version": snap.version, "stages": stages,
        "neo4j": {
            "configured": False, "mode": "fixture",
            "explanation": ("Neo4j stores entities as nodes and typed relationships as edges, and Cypher "
                            "retrieves the subgraph to display. It does not decide paths, scores or fixes: "
                            "Python modules do that. A stored relationship does not prove access is "
                            "feasible. Neo4j is not connected in this mode; this view comes from the "
                            "in-memory graph, and the browser never holds database credentials."),
            "would_write": {"nodes": len(snap.entities), "relationships_by_type": dict(rel),
                            "overlays": {"ATTACK_PATH": hops, "FIX": len(ov["fixes"]),
                                         "BACKUP_ROUTE": backup_edges, "ACCESS_LOST": len(ov["access_lost"])}},
        },
    }


def recommendations(scenario_id: str) -> dict:
    ov = overlays.overlays(scenario_id)
    return {
        "scenario_id": scenario_id, "graph_version": ov["graph_version"],
        "execution_mode": "SIMULATION_ONLY", "applied_to_cloud": False,
        "search_truncated": ov["search_truncated"], "summary": ov["summary"], "warnings": ov["warnings"],
        "recommendations": [{**f, "rank": i, "requires_human_approval": True,
                             "verification_status": "SIMULATED"} for i, f in enumerate(ov["fixes"], 1)],
    }


def access_requirements(scenario_id: str) -> dict:
    fixture = service._fixture(scenario_id)
    snap = service._build(scenario_id).snapshot
    f = service.ORG / "access" / f"{fixture.stem}.access.json"
    base = {"scenario_id": scenario_id, "graph_version": snap.version}
    if not f.exists():
        return {**base, "requirements_loaded": False, "requirements": [],
                "warnings": ["No access requirements sidecar for this scenario."]}
    spec = json.loads(f.read_text(encoding="utf-8"))
    names = {n.name for n in snap.entities if val(n.entity_type) != "iam_policy"}
    reqs, warnings = [], []
    for r in spec.get("requirements", []):
        who, what, trusted = r.get("principal"), r.get("resource"), list(r.get("trusted", []))
        missing = [x for x in [who, what, *trusted] if x not in names]
        if missing:
            warnings.append(f"{who} -> {what}: name(s) not found in scenario: {', '.join(map(str, missing))}")
        reqs.append({"principal": who, "resource": what, "trusted": trusted,
                     "max_hops": r.get("max_hops", 4), "names_resolved": not missing})
    return {**base, "requirements_loaded": True, "requirements": reqs, "warnings": warnings}
