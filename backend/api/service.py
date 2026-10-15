"""Read-only analysis service: fixture -> GraphSnapshot -> paths. No AWS or Neo4j calls."""
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from backend.ingestion.snapshot import build_snapshot_from_file
from backend.paths import discover_paths
from backend.remediation.scoring import rank_paths
from contracts import Criticality, GraphSnapshot, PathOptions

ROOT = Path(__file__).resolve().parents[2]
ORG = ROOT / "fixtures" / "organization"
T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)  # same as exporter: reproducible output

AUTHORIZATION = {"can_assume", "can_pass_role", "can_read", "can_write",
                 "can_invoke", "can_modify_policy", "can_decrypt"}
CONTEXT = {"runs_as"}
# TODO(P1): replace with the agreed relation-family classification in contracts.

ENTRY_TYPES = {"iam_user", "ec2_instance", "external_principal"}  # same heuristic as export_neo4j_green.py
val = lambda x: getattr(x, "value", x)

class UnknownScenario(Exception):
    pass
def list_scenarios() -> list[dict]:
    out = []
    for f in sorted(ORG.glob("scenario_*.json")):
        access = ORG / "access" / f"{f.stem}.access.json"
        out.append({"scenario_id": f.stem, "title": f.stem.replace("_", " "),
                    "data_mode": "synthetic", "has_access_requirements": access.exists()})
    return out


def _fixture(scenario_id: str) -> Path:
    known = {s["scenario_id"] for s in list_scenarios()}
    if scenario_id not in known:          # whitelist: never build a path from user input
        raise UnknownScenario(scenario_id)
    return ORG / f"{scenario_id}.json"


@lru_cache(maxsize=16)
def _build(scenario_id: str):
    return build_snapshot_from_file(_fixture(scenario_id), created_at=T0)


def _identity_class(entity_type: str) -> str:
    if entity_type == "external_principal": return "EXTERNAL_PRINCIPAL"
    if entity_type == "iam_policy": return "POLICY"
    if entity_type in {"secret", "s3_bucket", "kms_key"}: return "RESOURCE"
    return "UNKNOWN"   # an IAM role is NOT assumed to be an NHI; needs context from Person 1


def _family(rel: str) -> str:
    return "authorization" if rel in AUTHORIZATION else "context" if rel in CONTEXT else "structure"


def graph(scenario_id: str) -> dict:
    built = _build(scenario_id)
    snap = built.snapshot
    nodes = [{**e.model_dump(mode="json"), "entity_type": val(e.entity_type),
              "identity_class": _identity_class(val(e.entity_type))} for e in snap.entities]
    edges = [{**r.model_dump(mode="json"), "relation_type": val(r.relation_type),
              "family": _family(val(r.relation_type))} for r in snap.edges]
    return {"scenario_id": scenario_id, "graph_version": snap.version,
            "observed_at": snap.created_at.isoformat(), "data_mode": "synthetic",
            "warnings": list(built.warnings), "nodes": nodes, "edges": edges}


def _scores(snap, found, targets) -> dict:
    """P4 relative route scores per path_id.

    The ingested data has no criticality, so for SCORING ONLY the targets are treated as CRITICAL
    (same rule as export_neo4j_green.py). Without that, P4 returns no score at all. The likelihood is a
    relative route score, not a probability.
    """
    tset = set(targets)
    ents = tuple(n.model_copy(update={"criticality": Criticality.CRITICAL}) if n.entity_id in tset else n
                 for n in snap.entities)
    scored = GraphSnapshot(version=snap.version, created_at=snap.created_at, entities=ents, edges=snap.edges)
    return {a.path_id: a for a in rank_paths(list(found), scored)}


def paths(scenario_id: str) -> dict:
    snap = _build(scenario_id).snapshot
    entries = [n.entity_id for n in snap.entities if val(n.entity_type) in ENTRY_TYPES]
    admin = {n.entity_id for n in snap.entities if n.name == "AdministratorAccess"}
    targets = [e.source_id for e in snap.edges
               if e.target_id in admin and val(e.relation_type) == "has_policy"]
    res = discover_paths(snap, entries, targets, PathOptions(include_blocked=True))
    st = res.stats
    scores = _scores(snap, res.paths, targets)

    def row(p):
        a = scores.get(p.path_id)
        return {**p.model_dump(mode="json"), "feasibility": val(p.feasibility_status),
                "likelihood_score": a.likelihood_score if a else None,
                "impact_score": a.impact_score if a else None,
                "risk_score": a.risk_score if a else None,
                "confidence": a.confidence if a else "unknown",
                "score_reasons": list(a.reasons) if a else [],
                "score_unknowns": list(a.unknowns) if a else []}

    return {
        "scenario_id": scenario_id, "graph_version": snap.version,
        "search": {"max_depth": 5, "max_paths": 1000, "truncated": st.truncated,
                   "truncation_reason": st.truncation_reason, "paths_found": st.paths_found,
                   "unknown_entry_ids": list(st.unknown_entry_ids),
                   "unknown_target_ids": list(st.unknown_target_ids)},
        "assumptions": ["Entry points = users, EC2 instances, external principals (heuristic).",
                        "Targets = holders of AdministratorAccess (heuristic, not from metadata).",
                        "Scores are relative route scores (0 to 1), not probabilities. Targets are treated "
                        "as CRITICAL for scoring only, because the data has no criticality yet.",
                        "Paths are potential routes under the model, not incident evidence."],
        "paths": [row(p) for p in res.paths],
    }
