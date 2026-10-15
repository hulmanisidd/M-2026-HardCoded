import pytest

from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.seed_data import SEED_NOW, load_into


def snap():
    repo = InMemoryGraphRepository(clock=lambda: SEED_NOW)
    seed = load_into(repo)
    return repo.snapshot(), seed


def test_fork_gets_new_deterministic_version_and_leaves_original():
    s, seed = snap()
    ids = [seed.edge_ids["E3"]]
    f1, f2 = s.fork(ids), s.fork(ids)
    assert f1.version != s.version
    assert f1.version == f2.version
    assert f1.version.startswith(s.version + "+fork-")
    assert f1.get_edge(ids[0]) is None
    assert s.get_edge(ids[0]) is not None
    assert len(f1.edges) == len(s.edges) - 1


def test_fork_rejects_unknown_edge():
    s, _ = snap()
    with pytest.raises(ValueError):
        s.fork(["e_missing"])


def test_unknown_and_stale_survive_snapshot_and_fork():
    s, seed = snap()
    f = s.fork([seed.edge_ids["E3"]])
    for snapshot in (s, f):
        assert snapshot.get_edge(seed.edge_ids["E10"]).status == "unknown"
        assert snapshot.get_edge(seed.edge_ids["E2"]).status == "stale"