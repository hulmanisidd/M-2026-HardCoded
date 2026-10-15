"""POST /simulate-remediation: what happens if the chosen fixes were applied. Simulation only.

Works on a forked copy of the snapshot (edge removal). Nothing touches AWS or Neo4j.
Fail closed: if either path search is truncated, the residual list is reported as a lower bound,
never as "all clear", and backup routes are not claimed as verified.
"""
import hashlib

import export_neo4j_green as exp
from backend.paths import discover_paths
from contracts import PathOptions

from . import overlays, service

MODE = "SIMULATION_ONLY"
val = service.val


class UnknownFix(Exception):
    pass


# In-memory only: runs are lost when the API restarts. Nothing is persisted or applied.
_RUNS: dict[str, dict] = {}


def remember(result: dict) -> None:
    _RUNS[result["run_id"]] = result
    while len(_RUNS) > 50:
        _RUNS.pop(next(iter(_RUNS)))


def get_run(run_id: str) -> dict | None:
    return _RUNS.get(run_id)


def _search(snap):
    entries = [n.entity_id for n in snap.entities if val(n.entity_type) in service.ENTRY_TYPES]
    admin = {n.entity_id for n in snap.entities if n.name == "AdministratorAccess"}
    targets = [e.source_id for e in snap.edges
               if e.target_id in admin and val(e.relation_type) == "has_policy"]
    res = discover_paths(snap, entries, targets, PathOptions(include_blocked=True))
    live = [p for p in res.paths if val(p.feasibility_status) != "blocked"]
    return live, bool(res.stats.truncated)


def simulate(scenario_id: str, fix_ids: list[str] | None) -> dict:
    fixture = service._fixture(scenario_id)
    snap = service._build(scenario_id).snapshot
    ov = overlays.overlays(scenario_id)
    by_id = {f["id"]: f for f in ov["fixes"]}
    if fix_ids is None:
        chosen = list(ov["fixes"])
    else:
        missing = [i for i in fix_ids if i not in by_id]
        if missing:
            raise UnknownFix(", ".join(missing))
        chosen = [by_id[i] for i in dict.fromkeys(fix_ids)]
    cut = sorted({e for f in chosen for e in f["edge_ids"]})
    name = {n.entity_id: n.name for n in snap.entities}
    warnings: list[str] = []

    before, trunc_before = _search(snap)
    after, trunc_after = _search(snap.fork(tuple(cut)))
    truncated = trunc_before or trunc_after
    after_ids = {p.path_id for p in after}
    # A fork only removes edges, so anything found after the cut existed before; add it back if a
    # capped search missed it.
    seen = {p.path_id for p in before}
    before = before + [p for p in after if p.path_id not in seen]

    def row(p):
        return {"path_id": p.path_id, "node_ids": list(p.node_ids), "edge_ids": list(p.edge_ids),
                "route": " -> ".join(name.get(n, n) for n in p.node_ids),
                "feasibility": val(p.feasibility_status)}

    removed = [row(p) for p in before if p.path_id not in after_ids]
    residual = [row(p) for p in after]
    if truncated:
        warnings.append("Path search was truncated: residual paths are a lower bound, so an empty "
                        "residual list is not proof the fixes are enough.")

    preserved, lost = [], []
    access_file = service.ORG / "access" / f"{fixture.stem}.access.json"
    access_loaded = access_file.exists()
    if access_loaded and cut:
        try:
            b_rows, l_rows, lines = exp.reroute_rows(fixture, fixture.stem, tuple(cut), access_file, True)
            warnings += [ln.strip() for ln in lines if "skipped" in ln]
            warnings.append("Backup routes assume the collected policy edges are confirmed.")
            for r in l_rows:
                lost.append({"principal": r["key"].split(">")[0], "resource": r["key"].split(">")[1],
                             "reason": r["why"]})
            done = set()
            for r in b_rows:
                if r["route_id"] in done:
                    continue
                done.add(r["route_id"])
                if truncated or not r["simulated_safe"]:
                    lost.append({"principal": r["principal"], "resource": r["resource"],
                                 "reason": "A backup route exists but could not be verified "
                                           "(truncated search or not simulated safe)."})
                else:
                    preserved.append({"principal": r["principal"], "resource": r["resource"],
                                      "route": r["route"], "replaces": r["replaces"]})
        except Exception as exc:  # fail closed and visible
            preserved, lost = [], []
            warnings.append(f"Access check failed ({type(exc).__name__}: {exc}); "
                            "legitimate-access impact is unknown.")
    elif not access_loaded:
        warnings.append("No access requirements for this scenario: legitimate-access impact was not checked.")

    run_id = "run_" + hashlib.sha256(
        f"{scenario_id}|{snap.version}|{','.join(cut)}".encode()).hexdigest()[:12]
    return {
        "run_id": run_id, "scenario_id": scenario_id, "graph_version": snap.version,
        "execution_mode": MODE, "applied_to_cloud": False,
        "fixes_simulated": [{"id": f["id"], "label": f["label"], "edge_ids": f["edge_ids"]} for f in chosen],
        "cut_edge_ids": cut,
        "search_truncated": truncated,
        "paths": {"before": len(before), "removed": removed, "residual": residual,
                  "residual_is_lower_bound": truncated},
        "access": {"requirements_loaded": access_loaded, "preserved_via_backup": preserved,
                   "lost": lost,
                   "note": "Only requirements whose primary route is cut by these fixes are listed."},
        "approval": {"requires_human_approval": True, "status": "NOT_REQUESTED",
                     "reason": "MVP rule: every change needs human approval. Owner and approver data "
                               "is not available yet."},
        "warnings": warnings,
    }
