"""Every fixtures/organization/<name>.json is checked against
fixtures/expected_results/<name>.edges.json.

Expected files are written by hand from the scenario design (who SHOULD be
able to do what), not copied from program output, so they can catch bugs.
Names are entity names; they are unique inside each scenario.
"""
import json
from pathlib import Path

import pytest

from backend.ingestion.snapshot import build_snapshot_from_file

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = sorted((ROOT / "fixtures" / "organization").glob("scenario_*.json"))
NOW = __import__("datetime").datetime(2026, 10, 14, tzinfo=__import__("datetime").timezone.utc)


def load(path):
    expected = json.loads(
        (ROOT / "fixtures" / "expected_results" / f"{path.stem}.edges.json").read_text()
    )
    result = build_snapshot_from_file(path, created_at=NOW)
    snapshot = result.snapshot
    by_name = {}
    for entity in snapshot.entities:
        assert entity.name not in by_name, f"duplicate name {entity.name} in {path.stem}"
        by_name[entity.name] = entity.entity_id
    return expected, result, snapshot, by_name


def find_edge(snapshot, by_name, item):
    source, target = by_name[item["source"]], by_name[item["target"]]
    for edge in snapshot.get_neighbors(source):
        if edge.target_id == target and str(edge.relation_type) == item["relation"]:
            return edge
    return None


def test_every_scenario_has_expected_results():
    assert len(SCENARIOS) >= 4
    for path in SCENARIOS:
        assert (ROOT / "fixtures" / "expected_results" / f"{path.stem}.edges.json").exists(), path.stem


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
def test_expected_edges_exist(path):
    expected, _, snapshot, by_name = load(path)
    for item in expected["must_exist"]:
        edge = find_edge(snapshot, by_name, item)
        assert edge is not None, f"missing: {item}"
        if "conditions" in item:
            assert edge.conditions == item["conditions"], item


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
def test_forbidden_edges_absent(path):
    expected, _, snapshot, by_name = load(path)
    for item in expected["must_not_exist"]:
        assert find_edge(snapshot, by_name, item) is None, f"should not exist: {item}"


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
def test_scenarios_build_cleanly(path):
    _, result, _, _ = load(path)
    assert result.warnings == ()


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.stem)
def test_intended_attack_path_is_walkable(path):
    """Each hop of the intended path is an outgoing edge in the graph."""
    expected, _, snapshot, by_name = load(path)
    hops = expected.get("intended_attack_path")
    if not hops:
        pytest.skip("no intended path in this scenario")
    for here, there in zip(hops, hops[1:]):
        targets = {e.target_id for e in snapshot.get_neighbors(by_name[here])}
        assert by_name[there] in targets, f"no edge {here} -> {there}"
