import pytest
from fastapi.testclient import TestClient

import webapp.app as appmod
from webapp.app import SCENARIOS, app

client = TestClient(app)
NAMES = list(SCENARIOS)


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    appmod._hits.clear()


def test_samples_has_8():
    r = client.get("/api/samples")
    assert r.status_code == 200
    items = r.json()["scenarios"]
    assert len(items) == 8
    assert all(set(i) == {"name", "label"} for i in items)


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("fail", ["false", "true"])
def test_analyze_contract(name, fail):
    r = client.get(f"/api/analyze/{name}?fail={fail}")
    assert r.status_code == 200
    d = r.json()
    assert set(d) == {"title", "version", "now", "nodes", "edges", "paths"}
    assert d["title"] == name
    node_keys = {n["key"] for n in d["nodes"]}
    for n in d["nodes"]:
        assert {"key", "id", "name", "type", "crit", "account", "col", "row"} <= set(n)
    for e in d["edges"]:
        assert {"key", "src", "dst", "rel", "status", "visual", "conditions", "valid_until"} <= set(e)
        assert e["src"] in node_keys and e["dst"] in node_keys
    edge_keys = {e["key"] for e in d["edges"]}
    for p in d["paths"]:
        assert set(p["edges"]) <= edge_keys
        assert p["feasibility"] in {"feasible_under_model", "conditional", "blocked"}


def test_empty_paths_scenarios():
    for n in ("scenario_03_deny_and_conditions", "scenario_04_policy_self_edit"):
        assert client.get(f"/api/analyze/{n}").json()["paths"] == []


def test_fail_mode_changes_output():
    n = "scenario_01_passrole_escalation"
    assert client.get(f"/api/analyze/{n}").json() != client.get(f"/api/analyze/{n}?fail=true").json()


@pytest.mark.parametrize("bad", [
    "nope", "../../etc/passwd", "..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%5c%2e%2e%5cwindows", "scenario_01_passrole_escalation.json", "scenario_01_passrole_escalation%00",
    "SCENARIO_01_PASSROLE_ESCALATION", "",
])
def test_unknown_or_traversal_is_404(bad):
    r = client.get(f"/api/analyze/{bad}")
    assert r.status_code == 404
    assert "root:" not in r.text


def test_bad_fail_value_is_generic_422():
    r = client.get("/api/analyze/scenario_01_passrole_escalation?fail=banana")
    assert r.status_code == 422 and r.json() == {"detail": "invalid request"}


def test_repo_files_not_served():
    for p in ("/static/../build_live_graph.py", "/build_live_graph.py", "/.git/config", "/fixtures/organization/scenario_01_passrole_escalation.json",
              "/static/%2e%2e/build_live_graph.py", "/docs", "/openapi.json", "/redoc"):
        assert client.get(p).status_code in (404, 503), p


def test_security_headers():
    r = client.get("/api/samples")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "access-control-allow-origin" not in r.headers


def test_rate_limit():
    codes = [client.get("/api/samples").status_code for _ in range(appmod.RATE_LIMIT + 5)]
    assert codes[: appmod.RATE_LIMIT] == [200] * appmod.RATE_LIMIT
    assert codes[-1] == 429


def test_unexpected_error_is_generic(monkeypatch):
    class Boom:
        def get(self, *a, **k):
            raise RuntimeError("secret internals /etc/passwd")
    monkeypatch.setattr(appmod, "CACHE", Boom())
    r = TestClient(app, raise_server_exceptions=False).get("/api/analyze/scenario_01_passrole_escalation")
    assert r.status_code == 500
    assert r.json() == {"detail": "internal error"}
    assert "secret" not in r.text and "Traceback" not in r.text
