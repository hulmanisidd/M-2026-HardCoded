"""Rerouting on top of P3 (real path engine) and P4 (real optimizer)."""
from functools import partial

from backend.paths.engine import find_paths
from backend.remediation.candidates import generate_candidates
from backend.remediation.optimizer import OptimizerConstraints, greedy_select
from backend.rerouting.models import AccessRequirement, Outcome
from backend.rerouting.service import removed_edge_ids_of, reroute
from tests.unit.rerouting_graphs import A, build, eid

FINDER = partial(find_paths, entry_points=("attacker",), targets=("bucket",))
REQ = AccessRequirement(principal_id="dev", resource_id="bucket")


def p4_chosen(g, constraints):
    return greedy_select(generate_candidates(FINDER(g), g), g, FINDER, constraints).chosen


def test_p4_fix_then_reroute_then_protect_backup():
    g = build(extra=[("attacker", A, "ops")])
    must_cut = eid(g, "ops", "bucket")
    chosen = p4_chosen(g, OptimizerConstraints(mandatory_edge_ids=frozenset({must_cut})))
    removed = removed_edge_ids_of(chosen)
    assert must_cut in removed

    rep = reroute(g, REQ, removed, find_attack_paths=FINDER, attack_search_complete=True)
    assert rep.outcome is Outcome.BACKUP_RECOMMENDED
    assert rep.selected_backup.node_ids == ("dev", "backup", "bucket")

    # feed the recommendation back to P4 so it will not remove the backup route
    protected = frozenset(rep.protected_edge_ids)
    again = p4_chosen(g, OptimizerConstraints(mandatory_edge_ids=frozenset({must_cut}),
                                              forbidden_edge_ids=protected))
    assert protected.isdisjoint(removed_edge_ids_of(again))


def test_p4_residual_risk_never_worsens_and_no_new_paths_after_switch():
    g = build(extra=[("attacker", A, "ops")])
    chosen = p4_chosen(g, OptimizerConstraints(mandatory_edge_ids=frozenset({eid(g, "ops", "bucket")})))
    rep = reroute(g, REQ, removed_edge_ids_of(chosen), find_attack_paths=FINDER, attack_search_complete=True)
    sim = rep.simulation
    assert not sim.new_attack_path_ids and sim.known_risk_after <= sim.known_risk_before
    assert set(sim.residual_after) <= set(sim.residual_before)      # removal can only shrink the set


def test_when_p4_would_cut_the_only_backup_we_say_so_instead_of_pretending():
    g = build(extra=[("attacker", A, "ops"), ("attacker", A, "backup")])
    chosen = p4_chosen(g, OptimizerConstraints(mandatory_edge_ids=frozenset({eid(g, "ops", "bucket")})))
    rep = reroute(g, REQ, removed_edge_ids_of(chosen), find_attack_paths=FINDER, attack_search_complete=True)
    assert rep.outcome in (Outcome.NO_VALID_BACKUP, Outcome.BACKUP_RECOMMENDED)
    if rep.outcome is Outcome.NO_VALID_BACKUP:
        assert rep.selected_backup is None and rep.protected_edge_ids == ()
    else:   # P4 also cut the exposed backup edge: the safe new route must not use any removed edge
        assert set(rep.selected_backup.edge_ids).isdisjoint(removed_edge_ids_of(chosen))


def test_module_never_imports_aws_or_graph_internals():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "backend" / "rerouting"
    banned = ("boto3", "botocore", "backend.graph", "neo4j", "requests", "subprocess")
    for f in root.glob("*.py"):
        text = f.read_text(encoding="utf-8")
        assert not [b for b in banned if f"import {b}" in text or f"from {b}" in text], f.name
