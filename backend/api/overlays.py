"""Read-only overlays for one scenario: FIX, BACKUP_ROUTE and ACCESS_LOST. Simulation only.

Reuses the logic in export_neo4j_green.py (remediation + rerouting). Nothing here touches AWS or Neo4j.

Fail closed:
- A backup route is only returned if it is simulated safe, every edge id exists in the API graph,
  and the attack-path search was NOT truncated. Anything else becomes an ACCESS_LOST entry with a reason.
- Any error while computing overlays returns empty overlays plus a visible warning, never a guess.
"""
from functools import lru_cache

import export_neo4j_green as exp  # repo-root script; importing it has no side effects

from . import service

MODE = "SIMULATION_ONLY"


def _lost(key: str, label: str, node_ids: list[str], note: str) -> dict:
    return {"id": f"lost:{key}", "label": label, "edge_ids": [], "node_ids": node_ids,
            "status": "no_verified_backup", "note": note}


_ACTION_TEXT = {  # action_type -> (short label template, what the change does)
    "restrict_role_trust": ("Stop {src} from assuming {dst}", "Edit the trust policy of {dst} so {src} can no longer assume it"),
    "remove_pass_role": ("Stop {src} from passing {dst}", "Remove the permission that lets {src} pass the role {dst} to a service"),
    "remove_policy_modification": ("Stop {src} from editing {dst}", "Remove the permission that lets {src} change {dst}"),
    "remove_read_permission": ("Stop {src} from reading {dst}", "Remove {src}'s read access to {dst}"),
    "remove_write_permission": ("Stop {src} from writing to {dst}", "Remove {src}'s write access to {dst}"),
    "remove_decrypt_permission": ("Stop {src} from decrypting with {dst}", "Remove {src}'s permission to decrypt with {dst}"),
    "remove_invoke_permission": ("Stop {src} from invoking {dst}", "Remove {src}'s permission to invoke {dst}"),
    "remove_group_membership": ("Remove {src} from {dst}", "Take {src} out of the group {dst}"),
    "detach_policy": ("Detach {dst} from {src}", "Detach the policy {dst} from {src}"),
}


def _short(arn: str) -> str:
    return str(arn).rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def _fix_text(f: dict, risk_before) -> tuple[str, str]:
    """Plain-language label and note for one proposed fix (no model jargon).

    Unknown action types get a generic but readable sentence built from the type name, so a new
    kind of fix never shows raw model jargon or crashes.
    """
    action = str(f.get("action_type", "change"))
    tpl = _ACTION_TEXT.get(action)
    src, dst = _short(f.get("src", "?")), _short(f.get("dst", "?"))
    n = f.get("blocks_paths", 0)
    left = f.get("paths_left_if_only_this")
    pct = ""
    if risk_before and f.get("risk_reduction") is not None:
        pct = f" (about {round(100 * f['risk_reduction'] / risk_before)}% of the total route risk)"
    if tpl is None:
        what = action.replace("_", " ")
        label = f.get("label") or f"Apply '{what}' between {src} and {dst}"
        what_does = f"Apply the change '{what}' between {src} and {dst}"
        tpl_label = label
    else:
        what_does = tpl[1].format(src=src, dst=dst)
        tpl_label = tpl[0].format(src=src, dst=dst)
    note = f"{what_does}. On its own this closes {n} dangerous route(s){pct}"
    note += f"; {left} would still be open." if left is not None else "."
    return tpl_label, note + " Simulation only, nothing is changed in AWS."


@lru_cache(maxsize=16)
def _compute(scenario_id: str) -> dict:
    fixture = service._fixture(scenario_id)          # raises UnknownScenario for bad ids
    api_snap = service._build(scenario_id).snapshot
    known_edges = {e.edge_id for e in api_snap.edges}
    truncated = bool(service.paths(scenario_id)["search"]["truncated"])

    warnings: list[str] = []
    fixes: list[dict] = []
    backups: list[dict] = []
    lost: list[dict] = []
    summary = None
    access_loaded = False

    try:
        snap, _now, _n_events = exp.build_snap(fixture, False)
        _rows, fix_rows, summ = exp.attack_path_rows(snap, fixture.stem)

        if truncated:
            warnings.append("Attack-path search was truncated: fixes are partial and backup routes "
                            "cannot be verified.")

        for f in fix_rows:
            eid = f["cuts_edge"]
            if eid not in known_edges:
                warnings.append(f"Fix {f['fix_id']} cuts edge {eid}, which is not in the API graph; skipped.")
                continue
            label, note = _fix_text(f, (summ or {}).get("before"))
            fixes.append({
                "id": f["fix_id"], "label": label, "edge_ids": [eid],
                "status": "proposed_partial_search" if truncated else "proposed",
                "note": note,
            })

        if summ:
            summary = {"fixes": summ["fixes"], "risk_before": summ["before"],
                       "risk_after": summ["after"], "paths_left": summ["paths_left"]}

        access_file = service.ORG / "access" / f"{fixture.stem}.access.json"
        access_loaded = access_file.exists()
        if access_loaded and summ and summ["cut_edge_ids"]:
            b_rows, l_rows, lines = exp.reroute_rows(fixture, fixture.stem, summ["cut_edge_ids"],
                                                     access_file, True)
            warnings += [ln.strip() for ln in lines if "skipped" in ln]
            warnings.append("Backup routes assume the collected policy edges are confirmed "
                            "(ingestion marks them inferred).")

            for r in l_rows:
                lost.append(_lost(r["key"], r["label"], [r["src"], r["dst"]], r["why"]))

            routes: dict[str, dict] = {}
            for r in b_rows:
                g = routes.setdefault(r["route_id"], {"hops": {}, "row": r, "nodes": []})
                g["hops"][r["hop"]] = r["via_edge_id"]
                g["nodes"] += [r["src"], r["dst"]]
            for rid, g in routes.items():
                r = g["row"]
                edge_ids = [g["hops"][h] for h in sorted(g["hops"])]
                key = f"{r['principal']}>{r['resource']}"
                label = f"No verified backup | {r['principal']} -> {r['resource']}"
                nodes = [r["src"], r["dst"]]
                if truncated:
                    lost.append(_lost(key, label, nodes, "A backup route was found, but the attack-path "
                                      "search was truncated, so it cannot be verified."))
                elif not r["simulated_safe"]:
                    lost.append(_lost(key, label, nodes, "A backup route was found, but the simulation "
                                      "did not show it safe."))
                elif any(e not in known_edges for e in edge_ids):
                    lost.append(_lost(key, label, nodes, "A backup route was found, but some of its edges "
                                      "are not in the API graph."))
                else:
                    backups.append({
                        "id": rid, "label": f"Backup | {r['principal']} -> {r['resource']}",
                        "edge_ids": edge_ids, "status": "simulated_safe",
                        "note": (f"Route: {r['route']}. Replaces: {r['replaces']}. "
                                 f"Scenario risk {r['scenario_risk_before']} -> {r['scenario_risk_after']}."),
                    })
    except Exception as exc:  # fail closed and visible
        fixes, backups, lost, summary = [], [], [], None
        warnings.append(f"Overlay analysis failed ({type(exc).__name__}: {exc}). "
                        "No fixes or backup routes are shown.")

    return {"scenario_id": scenario_id, "graph_version": api_snap.version, "mode": MODE,
            "applied_to_cloud": False, "search_truncated": truncated,
            "access_requirements_loaded": access_loaded, "warnings": warnings, "summary": summary,
            "fixes": fixes, "backup_routes": backups, "access_lost": lost}


def overlays(scenario_id: str) -> dict:
    return _compute(scenario_id)