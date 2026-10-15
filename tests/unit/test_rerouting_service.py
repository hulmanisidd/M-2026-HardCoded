from functools import partial

import pytest

from backend.paths.engine import find_paths
from backend.rerouting.models import AccessRequirement, Outcome
from backend.rerouting.service import reroute
from contracts.entities import Entity
from contracts.graph import GraphSnapshot
from contracts.relationships import Relationship
from contracts.vocab import NodeType, RelationType
from tests.unit.rerouting_graphs import A, R, build, eid

FINDER = partial(find_paths, entry_points=("attacker",), targets=("bucket",))
REQ = AccessRequirement(principal_id="dev", resource_id="bucket")
ATTACKER_TO_OPS = ("attacker", A, "ops")
ATTACKER_TO_BACKUP = ("attacker", A, "backup")


def run(g, remove=(("ops", "bucket"),), req=REQ, complete=True, **kw):
    removed = tuple(eid(g, s, t) for s, t in remove)
    return reroute(g, req, removed, find_attack_paths=FINDER, attack_search_complete=complete, **kw)


def with_long_backup(g, safe_extra=()):
    """Add dev -> alt1 -> alt2 -> bucket (3 hops) on top of g."""
    ents = g.entities + tuple(Entity(entity_id=n, entity_type=NodeType.IAM_ROLE, name=n)
                              for n in ("alt1", "alt2"))
    def e(s, t, r):
        return Relationship(source_id=s, target_id=t, relation_type=r, status="confirmed",
                            evidence_ids=(f"ev:{s}>{t}",))
    edges = g.edges + (e("dev", "alt1", A), e("alt1", "alt2", A), e("alt2", "bucket", R))
    return GraphSnapshot(version=g.version, created_at=g.created_at, entities=ents, edges=edges)


def test_valid_backup_is_recommended_after_primary_is_removed():
    g = build(extra=[ATTACKER_TO_OPS])
    rep = run(g)
    assert rep.outcome is Outcome.BACKUP_RECOMMENDED
    assert rep.primary.node_ids == ("dev", "ops", "bucket")
    assert rep.selected_backup.node_ids == ("dev", "backup", "bucket")
    assert rep.simulation.is_safe and rep.simulation.access_preserved
    assert rep.protected_edge_ids == rep.selected_backup.edge_ids
    assert rep.mode == "simulated_recommendation_only"


def test_primary_still_valid_when_plan_does_not_touch_it():
    g = build()
    req = AccessRequirement(principal_id="dev", resource_id="bucket",
                            primary_edge_ids=(eid(g, "dev", "ops"), eid(g, "ops", "bucket")))
    rep = run(g, req=req, remove=(("backup", "bucket"),))
    assert rep.outcome is Outcome.PRIMARY_STILL_VALID and rep.selected_backup is None


def test_without_usage_data_the_affected_route_is_assumed_to_be_the_primary():
    g = build()
    rep = run(g, remove=(("backup", "bucket"),))     # no primary_edge_ids given
    assert rep.primary.node_ids == ("dev", "backup", "bucket")
    assert rep.outcome is Outcome.BACKUP_RECOMMENDED
    assert rep.selected_backup.node_ids == ("dev", "ops", "bucket")
    assert any("primary assumed" in n for n in rep.notes)


def test_primary_that_survives_but_is_exposed_gets_rerouted():
    g = build(extra=[ATTACKER_TO_OPS])
    rep = run(g, remove=(("dev", "escalator"),))      # ops>bucket survives, attacker reaches it
    assert rep.outcome is Outcome.BACKUP_RECOMMENDED
    assert rep.selected_backup.node_ids == ("dev", "backup", "bucket")


def test_only_alternative_is_exposed_to_attacker_so_no_backup():
    g = build(extra=[ATTACKER_TO_OPS, ATTACKER_TO_BACKUP])
    rep = run(g)
    assert rep.outcome is Outcome.NO_VALID_BACKUP and rep.selected_backup is None
    assert any("untrusted entries" in n for n in rep.notes)


def test_exposed_alternative_is_fine_if_that_entry_is_trusted():
    g = build(extra=[ATTACKER_TO_OPS, ATTACKER_TO_BACKUP])
    req = AccessRequirement(principal_id="dev", resource_id="bucket", trusted_entry_ids=("attacker",))
    assert run(g, req=req).outcome is Outcome.BACKUP_RECOMMENDED


def test_missing_evidence_on_only_alternative_means_no_backup():
    g = build(extra=[ATTACKER_TO_OPS], no_evidence={"backup>bucket"})
    rep = run(g)
    assert rep.outcome is Outcome.NO_VALID_BACKUP
    assert any("no evidence_ids" in n for n in rep.notes)


def test_stale_alternative_is_not_trusted():
    g = build(extra=[ATTACKER_TO_OPS], statuses={"dev>backup": "stale"})
    assert run(g).outcome is Outcome.NO_VALID_BACKUP


def test_conditional_alternative_without_evaluator_is_not_trusted():
    g = build(extra=[ATTACKER_TO_OPS], conditions={"backup>bucket": {"aws:MultiFactorAuthPresent": "true"}})
    assert run(g).outcome is Outcome.NO_VALID_BACKUP


def test_unavailable_backup_route_is_never_recommended():
    g = build(extra=[ATTACKER_TO_OPS])
    req = AccessRequirement(principal_id="dev", resource_id="bucket",
                            unavailable_edge_ids=(eid(g, "backup", "bucket"),))
    rep = run(g, req=req)
    assert rep.outcome is Outcome.NO_VALID_BACKUP


def test_no_alternative_route_exists_at_all():
    g = build(extra=[ATTACKER_TO_OPS], drop={"dev>backup", "backup>bucket", "dev>escalator", "escalator>bucket"})
    rep = run(g)
    assert rep.outcome is Outcome.NO_VALID_BACKUP and rep.assessments  # primary assessed, nothing else
    assert any("0 alternative" in n for n in rep.notes)


def test_privilege_escalation_route_is_never_a_backup():
    g = build(extra=[ATTACKER_TO_OPS], drop={"dev>backup", "backup>bucket"})
    rep = run(g)
    assert rep.outcome is Outcome.NO_VALID_BACKUP
    assert any("non-legitimate relation" in n for n in rep.notes)


def test_incomplete_attack_search_blocks_recommendation():
    g = build(extra=[ATTACKER_TO_OPS])
    assert run(g, complete=False).outcome is Outcome.NO_VALID_BACKUP


def test_truncated_route_search_is_reported_not_hidden():
    g = build(extra=[ATTACKER_TO_OPS])
    req = AccessRequirement(principal_id="dev", resource_id="bucket", max_hops=1)
    rep = run(g, req=req)
    assert rep.search_truncated and any("NOT proven" in n for n in rep.notes)


def test_shortest_verified_backup_wins_and_failed_candidate_falls_through():
    g = with_long_backup(build(extra=[ATTACKER_TO_OPS]))
    assert run(g).selected_backup.hops == 2
    g2 = with_long_backup(build(extra=[ATTACKER_TO_OPS, ATTACKER_TO_BACKUP]))
    rep = run(g2)                                     # short backup exposed -> long one is chosen
    assert rep.outcome is Outcome.BACKUP_RECOMMENDED and rep.selected_backup.node_ids[1] == "alt1"


def test_unverifiable_primary_is_reported_not_guessed():
    g = build(extra=[ATTACKER_TO_OPS], no_evidence={"dev>ops", "ops>bucket", "dev>backup",
                                                    "backup>bucket", "dev>escalator", "escalator>bucket"})
    assert run(g).outcome is Outcome.PRIMARY_UNVERIFIABLE
    bad = AccessRequirement(principal_id="dev", resource_id="bucket", primary_edge_ids=("e_nope",))
    rep = run(build(extra=[ATTACKER_TO_OPS]), req=bad)
    assert rep.outcome is Outcome.PRIMARY_UNVERIFIABLE and any("invalid" in n for n in rep.notes)


def test_explicit_primary_is_respected():
    g = build()
    req = AccessRequirement(principal_id="dev", resource_id="bucket",
                            primary_edge_ids=(eid(g, "dev", "backup"), eid(g, "backup", "bucket")))
    rep = run(g, req=req, remove=(("backup", "bucket"),))
    assert rep.primary.node_ids == ("dev", "backup", "bucket")
    assert rep.selected_backup.node_ids == ("dev", "ops", "bucket")


def test_nothing_to_simulate_is_an_error_not_a_silent_success():
    with pytest.raises(ValueError):
        reroute(build(), REQ, (), find_attack_paths=FINDER, attack_search_complete=True)


def test_snapshot_is_never_mutated():
    g = build(extra=[ATTACKER_TO_OPS])
    before = g.model_dump_json()
    run(g)
    assert g.model_dump_json() == before
