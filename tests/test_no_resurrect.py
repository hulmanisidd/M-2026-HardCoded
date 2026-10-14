from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.seed_data import SEED_NOW, load_into
from contracts import EdgeStatus


def _repo():
    repo = InMemoryGraphRepository(clock=lambda: SEED_NOW)
    seed = load_into(repo)
    return repo, seed


def test_replay_does_not_resurrect():
    repo, seed = _repo()
    original = repo.get_edge(seed.edge_ids["E1"])
    repo.invalidate_edge(original.edge_id)
    v = repo.snapshot().version
    change = repo.upsert_edge(original)  # old CONFIRMED replay
    assert change.changed is False
    assert repo.get_edge(original.edge_id).status == EdgeStatus.INVALIDATED
    assert repo.snapshot().version == v


def test_reinstate_flag_restores():
    repo, seed = _repo()
    original = repo.get_edge(seed.edge_ids["E1"])
    repo.invalidate_edge(original.edge_id)
    change = repo.upsert_edge(original, reinstate=True)
    assert change.changed is True
    assert repo.get_edge(original.edge_id).status == EdgeStatus.CONFIRMED


def test_invalidated_upsert_still_allowed():
    repo, seed = _repo()
    e = repo.get_edge(seed.edge_ids["E1"])
    inv = e.model_copy(update={"status": EdgeStatus.INVALIDATED})
    assert repo.upsert_edge(inv).changed is True