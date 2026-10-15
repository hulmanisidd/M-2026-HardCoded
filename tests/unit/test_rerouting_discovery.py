from backend.rerouting.discovery import build_explicit_path, discover_access_paths
from backend.rerouting.models import AccessRequirement
from contracts.vocab import RelationType
from tests.unit.rerouting_graphs import build, eid

REQ = AccessRequirement(principal_id="dev", resource_id="bucket")


def test_discovers_all_routes_as_access_paths():
    d = discover_access_paths(build(), REQ)
    nodes = {p.node_ids for p in d.paths}
    assert ("dev", "ops", "bucket") in nodes and ("dev", "backup", "bucket") in nodes
    assert d.complete and all(p.principal_id == "dev" for p in d.paths)


def test_unknown_endpoint_makes_discovery_incomplete():
    d = discover_access_paths(build(), AccessRequirement(principal_id="ghost", resource_id="bucket"))
    assert d.paths == () and not d.complete and d.unknown_endpoints == ("ghost",)


def test_max_hops_truncation_is_reported_not_hidden():
    g = build(extra=[("ops", RelationType.CAN_ASSUME, "backup")])
    d = discover_access_paths(g, AccessRequirement(principal_id="dev", resource_id="bucket", max_hops=1))
    assert d.truncated and not d.complete


def test_explicit_primary_valid_and_invalid():
    g = build()
    good = (eid(g, "dev", "ops"), eid(g, "ops", "bucket"))
    p, why = build_explicit_path(g, REQ, good)
    assert p and why is None and p.node_ids == ("dev", "ops", "bucket")
    assert build_explicit_path(g, REQ, ("e_nope",))[0] is None
    assert build_explicit_path(g, REQ, good[:1])[1].startswith("route ends at")
    assert "does not continue" in build_explicit_path(g, REQ, good[::-1])[1]