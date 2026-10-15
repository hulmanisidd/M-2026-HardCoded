import pytest
from fastapi.testclient import TestClient

from backend.api.main import app

client = TestClient(app)
SCENARIOS = [s["scenario_id"] for s in client.get("/api/scenarios").json()]


@pytest.mark.parametrize("sid", SCENARIOS)
def test_pipeline_shape(sid):
    b = client.get(f"/api/scenarios/{sid}/pipeline").json()
    keys = [s["key"] for s in b["stages"]]
    assert keys == ["fixture", "entities", "relationships", "paths", "risk", "fix", "residual"]
    for s in b["stages"]:
        assert isinstance(s["warnings"], list)
    assert b["neo4j"]["configured"] is False
    graph = client.get(f"/api/scenarios/{sid}/graph").json()
    assert b["stages"][1]["count"] == len(graph["nodes"])
    assert b["stages"][2]["count"] == len(graph["edges"])


@pytest.mark.parametrize("sid", SCENARIOS)
def test_recommendations_are_simulated_and_need_approval(sid):
    b = client.get(f"/api/scenarios/{sid}/recommendations").json()
    assert b["applied_to_cloud"] is False and b["execution_mode"] == "SIMULATION_ONLY"
    for r in b["recommendations"]:
        assert r["requires_human_approval"] is True
        assert r["verification_status"] == "SIMULATED"


@pytest.mark.parametrize("sid", SCENARIOS)
def test_access_requirements_shape(sid):
    b = client.get(f"/api/scenarios/{sid}/access-requirements").json()
    assert isinstance(b["requirements"], list) and isinstance(b["warnings"], list)
    if not b["requirements_loaded"]:
        assert b["requirements"] == []


def test_unknown_scenario_is_404_everywhere():
    for path in ("pipeline", "recommendations", "access-requirements"):
        assert client.get(f"/api/scenarios/nope/{path}").status_code == 404


def test_run_roundtrip_and_unknown_run():
    sid = SCENARIOS[0]
    run = client.post(f"/api/scenarios/{sid}/simulate-remediation", json={"fix_ids": None}).json()
    got = client.get(f"/api/runs/{run['run_id']}")
    assert got.status_code == 200 and got.json()["run_id"] == run["run_id"]
    assert client.get("/api/runs/run_does_not_exist").status_code == 404
