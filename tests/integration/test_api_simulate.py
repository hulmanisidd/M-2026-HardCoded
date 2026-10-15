import pytest
from fastapi.testclient import TestClient

from backend.api.main import app

client = TestClient(app)
SCENARIOS = [s["scenario_id"] for s in client.get("/api/scenarios").json()]


def post(sid, body=None):
    return client.post(f"/api/scenarios/{sid}/simulate-remediation", json=body)


def test_unknown_scenario_is_404():
    assert post("nope").status_code == 404


def test_unknown_fix_is_400():
    assert post(SCENARIOS[0], {"fix_ids": ["does_not_exist"]}).status_code == 400


@pytest.mark.parametrize("sid", SCENARIOS)
def test_simulation_only_and_approval_gate(sid):
    r = post(sid)
    assert r.status_code == 200
    b = r.json()
    assert b["applied_to_cloud"] is False
    assert b["execution_mode"] == "SIMULATION_ONLY"
    assert b["approval"]["requires_human_approval"] is True


@pytest.mark.parametrize("sid", SCENARIOS)
def test_removed_and_residual_are_consistent(sid):
    b = post(sid).json()
    removed = {p["path_id"] for p in b["paths"]["removed"]}
    residual = {p["path_id"] for p in b["paths"]["residual"]}
    assert not removed & residual
    assert len(removed) + len(residual) == b["paths"]["before"]
    if b["search_truncated"]:
        assert b["paths"]["residual_is_lower_bound"] is True
        assert b["access"]["preserved_via_backup"] == []


def test_no_fixes_changes_nothing():
    b = post(SCENARIOS[0], {"fix_ids": []}).json()
    assert b["cut_edge_ids"] == [] and b["paths"]["removed"] == []