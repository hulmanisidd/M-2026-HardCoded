import pytest
from pydantic import ValidationError

from backend.rerouting.models import (
    AccessPath, AccessRequirement, CandidateAssessment, CheckName, CheckResult, Evidence,
    Outcome, ReroutingReport, SwitchSimulation, Verdict, REQUIRED_CHECKS,
)

EV = (Evidence(source="t", detail="d"),)


def path(pid="p"):
    return AccessPath(path_id=pid, graph_version="v1", principal_id="a", resource_id="c",
                      node_ids=("a", "b", "c"), edge_ids=("e1", "e2"))


def all_checks(verdict=Verdict.VERIFIED):
    return {c: CheckResult(check=c, verdict=verdict, reason="r", evidence=EV) for c in CheckName}


def sim(**kw):
    base = dict(backup_path_id="p", plan_id="pl", access_preserved=True, residual_before=("x",),
                residual_after=("x",), known_risk_before=1.0, known_risk_after=1.0)
    return SwitchSimulation(**{**base, **kw})


def test_verified_without_evidence_is_impossible():
    with pytest.raises(ValidationError):
        CheckResult(check=CheckName.AVAILABILITY, verdict=Verdict.VERIFIED)


def test_default_check_verdict_is_unknown():
    assert CheckResult(check=CheckName.AVAILABILITY).verdict is Verdict.UNKNOWN


def test_missing_check_means_unknown_never_verified():
    checks = all_checks()
    del checks[CheckName.AVAILABILITY]
    a = CandidateAssessment(path=path(), checks=checks)
    assert a.verdict is Verdict.UNKNOWN and "check not run" in " ".join(a.blockers)


def test_all_verified_is_verified_and_one_rejected_dominates():
    assert CandidateAssessment(path=path(), checks=all_checks()).verdict is Verdict.VERIFIED
    checks = all_checks()
    checks[CheckName.POLICY_CONSTRAINTS] = CheckResult(check=CheckName.POLICY_CONSTRAINTS,
                                                       verdict=Verdict.REJECTED, reason="no")
    checks[CheckName.AVAILABILITY] = CheckResult(check=CheckName.AVAILABILITY)
    assert CandidateAssessment(path=path(), checks=checks).verdict is Verdict.REJECTED


def test_all_checks_are_required():
    assert REQUIRED_CHECKS == frozenset(CheckName)


def test_access_path_shape_rules():
    with pytest.raises(ValidationError):
        AccessPath(path_id="p", graph_version="v1", principal_id="a", resource_id="c",
                   node_ids=("a", "b", "a", "c"), edge_ids=("e1", "e2", "e3"))
    with pytest.raises(ValidationError):
        AccessPath(path_id="p", graph_version="v1", principal_id="a", resource_id="z",
                   node_ids=("a", "c"), edge_ids=("e1",))


def test_requirement_rules_and_trusted_entries():
    with pytest.raises(ValidationError):
        AccessRequirement(principal_id="a", resource_id="a")
    with pytest.raises(ValidationError):
        AccessRequirement(principal_id="a", resource_id="b", primary_edge_ids=())
    r = AccessRequirement(principal_id="a", resource_id="b", trusted_entry_ids=("svc",))
    assert r.trusted_entries == {"a", "svc"}


def test_simulation_safety_flags():
    assert sim().is_safe
    assert not sim(access_preserved=False).is_safe
    assert not sim(residual_after=("x", "new")).is_safe
    assert not sim(unknown_after=("u",)).is_safe
    assert not sim(exposed_attack_path_ids=("x",)).is_safe
    assert not sim(known_risk_after=1.5).is_safe


def test_report_cannot_claim_backup_without_safe_simulation():
    req = AccessRequirement(principal_id="a", resource_id="c")
    with pytest.raises(ValidationError):
        ReroutingReport(requirement=req, graph_version="v1", outcome=Outcome.BACKUP_RECOMMENDED)
    with pytest.raises(ValidationError):
        ReroutingReport(requirement=req, graph_version="v1", outcome=Outcome.BACKUP_RECOMMENDED,
                        selected_backup=path(), simulation=sim(access_preserved=False))
    with pytest.raises(ValidationError):
        ReroutingReport(requirement=req, graph_version="v1", outcome=Outcome.NO_VALID_BACKUP,
                        selected_backup=path())
    ok = ReroutingReport(requirement=req, graph_version="v1", outcome=Outcome.BACKUP_RECOMMENDED,
                         selected_backup=path(), simulation=sim())
    assert ok.protected_edge_ids == ("e1", "e2")


def test_report_mode_cannot_be_deployed():
    req = AccessRequirement(principal_id="a", resource_id="c")
    with pytest.raises(ValidationError):
        ReroutingReport(requirement=req, graph_version="v1", outcome=Outcome.NO_VALID_BACKUP,
                        mode="deployed")
