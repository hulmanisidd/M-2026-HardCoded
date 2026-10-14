import pytest
from pydantic import ValidationError

from contracts.remediation import RemediationPlan, SimulationResult
from contracts.scoring import PathScore


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