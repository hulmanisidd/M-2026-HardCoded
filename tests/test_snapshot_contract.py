import inspect

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.seed_data import SEED_NOW, load_into
from contracts import GraphSnapshot


def _snap():
    repo = InMemoryGraphRepository(clock=lambda: SEED_NOW)
    seed = load_into(repo)
    return repo.snapshot(), seed


def test_signature_is_edge_id_context():
    params = list(inspect.signature(GraphSnapshot.check_transition).parameters)
    assert params == ["self", "edge_id", "context"]


def test_version_stable_and_string():
    a, _ = _snap()
    b, _ = _snap()
    assert isinstance(a.version, str) and a.version.startswith("g_")
    assert a.version == b.version


def test_entity_lookup():
    snap, seed = _snap()
    assert snap.get_entity(seed.entity_ids["alice"]).name == "alice"
    assert snap.get_entity("nope") is None
    assert snap.get_edge("nope") is None


def test_get_neighbors_outgoing_sorted_and_empty():
    snap, seed = _snap()
    nb = snap.get_neighbors(seed.entity_ids["dev-role"])
    ids = [e.edge_id for e in nb]
    assert ids == sorted(ids) and len(ids) == 4
    assert all(e.source_id == seed.entity_ids["dev-role"] for e in nb)
    assert snap.get_neighbors(seed.entity_ids["customer-data"]) == []
    assert snap.get_neighbors("nope") == []


def test_check_transition_results():
    snap, seed = _snap()
    t = lambda k: snap.check_transition(seed.edge_ids[k], {})
    assert t("E1").status.value == "feasible_under_model"
    assert t("E2").status.value == "conditional"   # stale
    assert t("E10").status.value == "conditional"  # unknown
    assert t("E9").status.value == "conditional"   # conditions
    assert t("E11").status.value == "blocked"      # expired
    assert t("E11").reason == "edge_expired"
    assert snap.check_transition("nope", {}).reason == "edge_not_found"


def test_context_is_ignored():
    snap, seed = _snap()
    e = seed.edge_ids["E9"]
    assert snap.check_transition(e, {}) == snap.check_transition(e, {"sts:ExternalId": "x"})