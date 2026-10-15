from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import overlays, service, simulate

app = FastAPI(title="HardCoded NHI API")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["GET", "POST"], allow_headers=["*"])


def _guard(fn, scenario_id: str):
    try:
        return fn(scenario_id)
    except service.UnknownScenario:
        raise HTTPException(404, f"unknown scenario: {scenario_id}")


class SimulateRequest(BaseModel):
    fix_ids: list[str] | None = None   # None = all proposed fixes


@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "fixture", "neo4j": "not_configured",
            "applied_to_cloud": False}


@app.get("/api/scenarios")
def scenarios():
    return service.list_scenarios()


@app.get("/api/scenarios/{scenario_id}/graph")
def graph(scenario_id: str):
    return _guard(service.graph, scenario_id)


@app.get("/api/scenarios/{scenario_id}/paths")
def paths(scenario_id: str):
    return _guard(service.paths, scenario_id)


@app.get("/api/scenarios/{scenario_id}/overlays")
def get_overlays(scenario_id: str):
    return _guard(overlays.overlays, scenario_id)


@app.post("/api/scenarios/{scenario_id}/simulate-remediation")
def simulate_remediation(scenario_id: str, body: SimulateRequest | None = None):
    fix_ids = body.fix_ids if body else None
    try:
        return simulate.simulate(scenario_id, fix_ids)
    except service.UnknownScenario:
        raise HTTPException(404, f"unknown scenario: {scenario_id}")
    except simulate.UnknownFix as exc:
        raise HTTPException(400, f"unknown fix id(s): {exc}")