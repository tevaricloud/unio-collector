"""Independent admission checks for actual neutral network projection output."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.loaders import Loader

from unio_collector.aws.network.projection import NESTED_FIELDS as PRODUCER_NESTED
from unio_collector.aws.network.projection import RESOURCE_FIELDS as PRODUCER_FIELDS
from unio_collector.aws.network.projection import project_fields
from unio_collector.privacy.network.facts import NESTED_FIELDS, RESOURCE_FIELDS, NetworkFactsPolicy

pytestmark = pytest.mark.offline

SHAPES = {
    "vpcs": "Vpc",
    "subnets": "Subnet",
    "route_tables": "RouteTable",
    "vpc_endpoints": "VpcEndpoint",
    "nat_gateways": "NatGateway",
    "network_interfaces": "NetworkInterface",
    "addresses": "Address",
    "transit_gateways": "TransitGateway",
    "transit_gateway_attachments": "TransitGatewayAttachment",
    "transit_gateway_route_tables": "TransitGatewayRouteTable",
    "vpc_endpoint_service_configurations": "ServiceConfiguration",
}


def _provider_value(shape: str, model: dict[str, Any], selected: tuple[str, ...] | None = None) -> Any:  # noqa: ANN401
    """Build synthetic SDK-shaped inputs independently from privacy type declarations."""
    definition = model[shape]
    if definition["type"] == "structure":
        return {key: _provider_value(definition["members"][key]["shape"], model, PRODUCER_NESTED.get(key)) for key in selected or ()}
    if definition["type"] == "list":
        return [_provider_value(definition["member"]["shape"], model, selected)]
    if definition["type"] == "boolean":
        return True
    if definition["type"] == "timestamp":
        return datetime(2026, 5, 20, tzinfo=UTC)
    assert definition["type"] == "string"
    return definition["enum"][0] if "enum" in definition else "synthetic-customer-value"


def test_independent_network_field_inventory() -> None:
    """Require every projected provider field and nested container to be reviewed."""
    assert {key: set(value) for key, value in RESOURCE_FIELDS.items()} == {key: set(value) for key, value in PRODUCER_FIELDS.items()}
    assert {key: set(value) for key, value in NESTED_FIELDS.items()} | {"TagSet": set(NESTED_FIELDS["Tags"])} == {
        key: set(value) for key, value in PRODUCER_NESTED.items()
    }
    model = Loader().load_service_model("ec2", "service-2")["shapes"]
    for kind, fields in RESOURCE_FIELDS.items():
        for name, spec in fields.items():
            if spec.startswith("enum:"):
                assert spec.removeprefix("enum:") == model[SHAPES[kind]]["members"][name]["shape"]


@pytest.mark.parametrize("kind", SHAPES)
def test_actual_projection_all_optional_fields(kind: str) -> None:
    """Run the actual projection on populated SDK-shaped optional and null members."""
    model = Loader().load_service_model("ec2", "service-2")["shapes"]
    original = _provider_value(SHAPES[kind], model, PRODUCER_FIELDS[kind])
    facts = project_fields(original, PRODUCER_FIELDS[kind])
    assert set(facts) == set(PRODUCER_FIELDS[kind])
    assert not NetworkFactsPolicy.unknown_paths(facts, kind, "facts")
    nullable = project_fields(dict.fromkeys(original), PRODUCER_FIELDS[kind])
    assert not NetworkFactsPolicy.unknown_paths(nullable, kind, "facts")
    assert not NetworkFactsPolicy.unknown_paths({}, kind, "facts")


@pytest.mark.parametrize("kind", SHAPES)
@pytest.mark.parametrize("value", [None, {}, [], "synthetic-customer", 1])
def test_unknown_fact_always_rejects(kind: str, value: object) -> None:
    """Unknown containers and nulls cannot disappear beneath strict omission."""
    assert NetworkFactsPolicy.unknown_paths({"unknown": value}, kind, "facts") == ["facts.unknown"]


@pytest.mark.parametrize("kind", SHAPES)
def test_wrong_kind_and_malformed_facts(kind: str) -> None:
    """A field valid for another kind remains unknown; roots must be objects."""
    other = next(field for fields in PRODUCER_FIELDS.values() for field in fields if field not in PRODUCER_FIELDS[kind])
    assert NetworkFactsPolicy.unknown_paths({other: None}, kind, "facts") == ["facts." + other]
    assert NetworkFactsPolicy.unknown_paths([], kind, "facts") == ["facts"]
    assert NetworkFactsPolicy.unknown_paths(None, kind, "facts") == ["facts"]
    assert NetworkFactsPolicy.unknown_paths({}, "unknown", "facts") == ["facts"]


@pytest.mark.parametrize(
    ("facts", "path"),
    [
        ({"Routes": [{"unknown": {}}]}, "facts.Routes[].unknown"),
        ({"Associations": [{"AssociationState": {"unknown": None}}]}, "facts.Associations[].AssociationState.unknown"),
        ({"Tags": [{"Key": "Name", "Value": "Synthetic", "unknown": []}]}, "facts.Tags[].unknown"),
        ({"Routes": [{"State": "unknown-provider-state"}]}, "facts.Routes[].State"),
        ({"Routes": [{"DestinationCidrBlock": {}}]}, "facts.Routes[].DestinationCidrBlock"),
        ({"Routes": [None]}, "facts.Routes[]"),
        ({"Associations": [{"Main": 1}]}, "facts.Associations[].Main"),
        ({"Routes[].State": "active"}, "facts.Routes[].State"),
    ],
)
def test_nested_unknown_and_malformed_rejection(facts: dict[str, Any], path: str) -> None:
    """Validate every nested branch, finite state and literal path spelling."""
    assert NetworkFactsPolicy.unknown_paths(facts, "route_tables", "facts") == [path]


@pytest.mark.parametrize("state", ["PendingAcceptance", "Pending", "Available", "Deleting", "Deleted", "Rejected", "Failed", "Expired", "Partial"])
def test_endpoint_state_historical_case(state: str) -> None:
    """Actual producer interpretation accepts finite state spellings case-insensitively."""
    for value in (state, state.lower(), state[0].lower() + state[1:]):
        assert not NetworkFactsPolicy.unknown_paths({"State": value}, "vpc_endpoints", "facts")
    assert NetworkFactsPolicy.unknown_paths({"State": state + "Customer"}, "vpc_endpoints", "facts") == ["facts.State"]
