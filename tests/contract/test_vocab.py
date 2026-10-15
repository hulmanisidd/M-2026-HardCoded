import pytest

from contracts.vocab import Criticality, NodeType, RelationType


def test_enums_behave_like_strings():
    assert NodeType.IAM_ROLE == "iam_role"
    assert RelationType("can_assume") is RelationType.CAN_ASSUME


def test_unknown_value_is_rejected():
    with pytest.raises(ValueError):
        Criticality("catastrophic")


def test_values_are_unique():
    for enum_cls in (NodeType, RelationType, Criticality):
        values = [m.value for m in enum_cls]
        assert len(values) == len(set(values))