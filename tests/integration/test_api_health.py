from fastapi.testclient import TestClient
from backend.api.main import app

client = TestClient(app)


def test_health_never_applies_changes():
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["applied_to_cloud"] is False


def test_scenarios_lists_all_eight_with_sidecar_flag():
    data = client.get("/api/scenarios").json()
    assert len(data) == 8
    flags = {s["scenario_id"]: s["has_access_requirements"] for s in data}
    assert flags["scenario_08_access_rerouting"] is True


def test_graph_and_paths_for_scenario_01():
    g = client.get("/api/scenarios/scenario_01_passrole_escalation/graph").json()
    assert g["nodes"] and g["edges"] and g["graph_version"]
    ids = {n["entity_id"] for n in g["nodes"]}
    assert all(e["source_id"] in ids and e["target_id"] in ids for e in g["edges"])
    p = client.get("/api/scenarios/scenario_01_passrole_escalation/paths").json()
    assert "truncated" in p["search"] and p["graph_version"] == g["graph_version"]


def test_unknown_scenario_is_404_and_path_traversal_rejected():
    assert client.get("/api/scenarios/nope/graph").status_code == 404
    assert client.get("/api/scenarios/..%2Fsecrets/graph").status_code == 404