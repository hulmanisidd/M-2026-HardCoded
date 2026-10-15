from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import overlays, service

app = FastAPI(title="HardCoded NHI API")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_methods=["GET", "POST"], allow_headers=["*"])


def _guard(fn, scenario_id: str):
    try:
        return fn(scenario_id)
    except service.UnknownScenario:
        raise HTTPException(404, f"unknown scenario: {scenario_id}")


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