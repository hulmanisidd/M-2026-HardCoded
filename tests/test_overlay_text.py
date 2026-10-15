from backend.api.overlays import _fix_text

ROW = {"action_type": "restrict_role_trust", "src": "arn:aws:iam::1:user/ben-billing",
       "dst": "arn:aws:iam::1:role/billing-gateway", "blocks_paths": 2, "risk_reduction": 0.36,
       "paths_left_if_only_this": 5, "label": "Fix 1 | restrict role trust"}


def test_label_names_the_role_and_user():
    label, note = _fix_text(ROW, 1.68)
    assert label == "Stop ben-billing from assuming billing-gateway"
    assert "trust policy of billing-gateway" in note and "21%" in note
    assert "->" not in note and "risk reduction" not in note


def test_unknown_action_keeps_original_label_and_no_percent_without_total():
    assert _fix_text({**ROW, "action_type": "weird_new_action"}, 1.68)[0] == ROW["label"]
    assert "%" not in _fix_text(ROW, None)[1]


def test_missing_fields_and_unknown_action_do_not_crash():
    label, note = _fix_text({"action_type": "brand_new_kind", "src": "x/a", "dst": "y/b"}, None)
    assert "a" in label and "b" in label
    assert "Simulation only" in note and "None" not in note
    assert _fix_text({}, 1.0)[0]
