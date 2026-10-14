import pytest
from pydantic import ValidationError

from contracts.paths import AttackPath, AttackStep
from contracts.remediation import RemediationPlan, SimulationResult
from contracts.scoring import PathScore


def step(e, s, t):
    return AttackStep(edge_id=e, source_id=s, target_id=t)


def test_valid_path_properties():
    p = AttackPath(id="p1", snapshot_version="v1", steps=(step("e1", "a", "b"), step("e2", "b", "c")))
    assert (p.entry_id, p.target_id, p.edge_ids) == ("a", "c", ("e1", "e2"))


def test_path_must_be_contiguous():
    with pytest.raises(ValidationError):
        AttackPath(id="p", snapshot_version="v1", steps=(step("e1", "a", "b"), step("e2", "x", "c")))


def test_path_rejects_cycles_and_empty():
    with pytest.raises(ValidationError):
        AttackPath(id="p", snapshot_version="v1",
                   steps=(step("e1", "a", "b"), step("e2", "b", "c"), step("e3", "c", "a")))
    with pytest.raises(ValidationError):
        AttackPath(id="p", snapshot_version="v1", steps=())


def test_step_rejects_self_loop_and_is_frozen():
    with pytest.raises(ValidationError):
        step("e1", "a", "a")
    s = step("e1", "a", "b")
    with pytest.raises(ValidationError):
        s.edge_id = "x"


def test_score_risk_and_bounds():
    assert PathScore(path_id="p", likelihood=0.5, impact=0.4).risk == 0.2
    with pytest.raises(ValidationError):
        PathScore(path_id="p", likelihood=1.5, impact=0.4)


def test_plan_rejects_duplicates_and_empty():
    with pytest.raises(ValidationError):
        RemediationPlan(id="r", base_version="v1", removed_edge_ids=("e1", "e1"))
    with pytest.raises(ValidationError):
        RemediationPlan(id="r", base_version="v1", removed_edge_ids=())


def test_simulation_blocked_paths():
    r = SimulationResult(plan_id="r", before_version="v1", after_version="v2",
                         paths_before=("p1", "p2"), paths_after=("p2",))
    assert r.blocked_path_ids == ("p1",)
    with pytest.raises(ValidationError):
        SimulationResult(plan_id="r", before_version="v1", after_version="v2",
                         paths_before=("p1",), paths_after=("p9",))