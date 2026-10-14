from datetime import timedelta
from backend.graph.memory_repository import InMemoryGraphRepository
from backend.graph.seed_data import SEED_NOW, load_into, build_seed


def test_replay_idempotent_and_version_stable():
    t = [SEED_NOW]
    repo = InMemoryGraphRepository(clock=lambda: t[0])
    seed = load_into(repo)
    v1 = repo.snapshot().version
    for e in seed.entities:
        assert repo.upsert_entity(e).changed is False
    for e in seed.edges:
        assert repo.upsert_edge(e).changed is False
    t[0] = SEED_NOW + timedelta(days=3)          # no window boundary crossed
    assert repo.snapshot().version == v1


def test_version_changes_when_edge_expires():
    t = [SEED_NOW - timedelta(days=40)]          # before Sep 1 expiry
    repo = InMemoryGraphRepository(clock=lambda: t[0])
    load_into(repo)
    before = repo.snapshot()
    t[0] = SEED_NOW
    after = repo.snapshot()
    assert before.version != after.version
    assert before.entities == after.entities and before.edges == after.edges