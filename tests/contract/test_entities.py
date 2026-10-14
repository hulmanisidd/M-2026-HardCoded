import pytest
from pydantic import ValidationError

from contracts.entities import Entity
from contracts.vocab import Criticality, NodeType


def make_entity(**overrides):
    data = {
        "entity_id": "arn:aws:iam::123456789012:role/admin",
        "entity_type": NodeType.IAM_ROLE,
        "name": "admin",
    }
    data.update(overrides)
    return Entity(**data)


def test_valid_entity_with_defaults():
    e = make_entity()
    assert e.criticality is None
    assert e.attributes == {}


def test_plain_strings_are_coerced_to_enums():
    e = make_entity(entity_type="iam_role", criticality="high")
    assert e.entity_type is NodeType.IAM_ROLE
    assert e.criticality is Criticality.HIGH


def test_unknown_entity_type_is_rejected():
    with pytest.raises(ValidationError):
        make_entity(entity_type="spaceship")


def test_empty_id_is_rejected():
    with pytest.raises(ValidationError):
        make_entity(entity_id="")


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        make_entity(colour="red")


def test_entity_is_immutable():
    e = make_entity()
    with pytest.raises(ValidationError):
        e.name = "changed"