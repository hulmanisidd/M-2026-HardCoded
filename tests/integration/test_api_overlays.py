import pytest
from fastapi.testclient import TestClient

from backend.api.main import app

client = TestClient(app)
SCENARIOS = [s["scenario_id"] for s in client.get("/api/scenarios").json()]


def test_unknown_scenario_is_404():
    assert client.get("/api/scenarios/nope/overlays").status_code == 404


@pytest.mark.parametrize("sid", SCENARIOS)
def test_overlays_shape_and_simulation_only(sid):
    body = client.get(f"/api/scenarios/{sid}/overlays").json()
    assert body["applied_to_cloud"] is False
    assert body["mode"] == "SIMULATION_ONLY"
    for key in ("fixes", "backup_routes", "access_lost", "warnings"):
        assert isinstance(body[key], list)
    for ov in body["fixes"] + body["backup_routes"] + body["access_lost"]:
        for k in ("id", "label", "edge_ids", "status", "note"):
            assert k in ov


@pytest.mark.parametrize("sid", SCENARIOS)
def test_overlay_edges_exist_in_graph(sid):
    body = client.get(f"/api/scenarios/{sid}/overlays").json()
    edges = {e["edge_id"] for e in client.get(f"/api/scenarios/{sid}/graph").json()["edges"]}
    for ov in body["fixes"] + body["backup_routes"]:
        assert set(ov["edge_ids"]) <= edges


@pytest.mark.parametrize("sid", SCENARIOS)
def test_fail_closed_when_truncated(sid):
    body = client.get(f"/api/scenarios/{sid}/overlays").json()
    if body["search_truncated"]:
        assert body["backup_routes"] == []