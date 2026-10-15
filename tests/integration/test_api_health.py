from fastapi.testclient import TestClient
from backend.api.main import app

client = TestClient(app)


def test_health_never_applies_changes():
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["applied_to_cloud"] is False



def test_scenarios_list_expected_ids_and_access_requirement_flags():
    response = client.get("/api/scenarios")
    assert response.status_code == 200

    data = response.json()

    expected_access_requirements = {
        "scenario_01_passrole_escalation": False,
        "scenario_02_role_chain": False,
        "scenario_03_deny_and_conditions": False,
        "scenario_04_policy_self_edit": False,
        "scenario_05_enterprise_multihop": False,
        "scenario_06_privesc_toolkit": False,
        "scenario_07_exposed_vs_defended": False,
        "scenario_08_access_rerouting": True,
        "scenario_09_pipeline_hardening": True,
    }

    actual_access_requirements = {
        scenario["scenario_id"]: scenario["has_access_requirements"]
        for scenario in data
    }

    assert actual_access_requirements == expected_access_requirements


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