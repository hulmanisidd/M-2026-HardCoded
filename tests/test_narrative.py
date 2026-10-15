from backend.api import narrative

LOST_REASON = ("primary route (ben-billing -> billing-gateway -> billing-ledger) is cut by the fix; "
               "36 alternative route(s) examined, none passed every check; "
               "route search was depth-limited, so longer routes are not ruled out")

REMOVED = [
    "ana-analyst -> analytics-gateway -> etl-admin",
    "ana-analyst -> analytics-gateway -> lake-admin",
    "ben-billing -> billing-gateway -> finance-admin",
    "ben-billing -> billing-gateway -> treasury-admin",
    "cat-ci -> ci-hub -> deploy-target -> release-admin",
    "cat-ci -> legacy-hub -> deploy-target -> release-admin",
    "contractor-dev -> legacy-hub -> deploy-target -> release-admin",
]


def _row(route):
    return {"path_id": route, "route": route, "node_ids": [], "edge_ids": [], "feasibility": "feasible_under_model"}


def _result(removed=REMOVED, residual=(), lost=True, truncated=False, loaded=True):
    return {
        "search_truncated": truncated, "fixes_simulated": [{"id": f"f{i}"} for i in range(3)],
        "paths": {"before": len(removed) + len(residual),
                  "removed": [_row(r) for r in removed], "residual": [_row(r) for r in residual]},
        "access": {"requirements_loaded": loaded,
                   "lost": [{"principal": "ben-billing", "resource": "billing-ledger", "reason": LOST_REASON}] if lost else [],
                   "preserved_via_backup": [{"principal": "ana-analyst", "resource": "reporting-reader",
                                             "route": "ana-analyst -> reports-gateway -> reporting-reader",
                                             "replaces": "x"}]},
        "approval": {"requires_human_approval": True},
        "warnings": ["Backup routes assume the collected policy edges are confirmed."],
    }


def test_route_sentence():
    assert narrative.describe_route("a -> b -> c") == "a can reach c through b"
    assert narrative.describe_route("a -> b") == "a can reach b directly"
    assert narrative.describe_route("a -> b -> c -> d") == "a can reach d through b then c"


def test_needs_review_when_access_lost():
    e = narrative.explain_simulation(_result())
    assert e["verdict"] == "NEEDS_REVIEW"
    assert "3 fixes" in e["headline"] and "7 of 7" in e["headline"] and "ben-billing to billing-ledger" in e["headline"]
    assert "36 other routes" in e["side_effects"][0]
    assert "limited in depth" in e["side_effects"][0]
    assert len(e["blocked"]) == 7 and e["still_open"] == []
    assert e["kept"] == ["ana-analyst keeps access to reporting-reader through a backup route "
                         "(ana-analyst -> reports-gateway -> reporting-reader)."]
    assert any("approver" in s for s in e["next_steps"])


def test_good_when_clean():
    e = narrative.explain_simulation(_result(lost=False))
    assert e["verdict"] == "GOOD" and "nothing legitimate breaks" in e["headline"]


def test_partial_and_ineffective():
    e = narrative.explain_simulation(_result(removed=REMOVED[:2], residual=REMOVED[2:], lost=False))
    assert e["verdict"] == "PARTIAL" and "5 still remain open" in e["headline"]
    e = narrative.explain_simulation(_result(removed=[], residual=REMOVED, lost=False))
    assert e["verdict"] == "INEFFECTIVE"


def test_truncated_never_looks_safe():
    e = narrative.explain_simulation(_result(lost=False, truncated=True))
    assert e["verdict"] == "UNVERIFIED"
    assert any("cut short" in c for c in e["cautions"])


def test_unchecked_access_is_not_called_safe():
    e = narrative.explain_simulation(_result(lost=False, loaded=False))
    assert any("unknown, not safe" in c for c in e["cautions"])


def test_to_text_has_all_sections():
    t = narrative.to_text(narrative.explain_simulation(_result()))
    for part in ("Closed routes:", "Side effects:", "Access kept:", "Next steps:"):
        assert part in t


# ---- robustness with new or odd inputs ----
def test_never_raises_on_odd_data():
    from backend.api.narrative import explain_simulation
    for bad in ({}, {"paths": None}, {"paths": {"removed": [{}], "residual": ["x"]}},
                {"access": {"lost": [{"reason": 5}]}, "paths": {"removed": [{"route": "a -> b"}]}}):
        x = explain_simulation(bad)
        assert x["verdict"] in {"GOOD", "NEEDS_REVIEW", "PARTIAL", "INEFFECTIVE", "UNVERIFIED"}
        assert x["headline"] and x["approval"] and isinstance(x["next_steps"], list)


def test_failure_degrades_to_unverified_not_good(monkeypatch):
    from backend.api import narrative
    monkeypatch.setattr(narrative, "_explain", lambda r: 1 / 0)
    x = narrative.explain_simulation({"paths": {"removed": [{"route": "a -> b"}]}})
    assert x["verdict"] == "UNVERIFIED"
