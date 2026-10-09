"""Independent, kind-specific admission of projected EC2 network facts."""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from typing import Any

from botocore.loaders import Loader

RESOURCE_FIELDS: dict[str, dict[str, str]] = {
    "vpcs": {"VpcId": "identifier", "Tags": "list:Tags"},
    "subnets": {"SubnetId": "identifier", "VpcId": "identifier", "AvailabilityZone": "region", "Tags": "list:Tags"},
    "route_tables": {"RouteTableId": "identifier", "VpcId": "identifier", "Routes": "list:Routes", "Associations": "list:Associations", "Tags": "list:Tags"},
    "vpc_endpoints": {
        "VpcEndpointId": "identifier",
        "VpcId": "identifier",
        "VpcEndpointType": "enum:VpcEndpointType",
        "ServiceName": "service",
        "State": "enum:State",
        "RouteTableIds": "identifiers",
        "SubnetIds": "identifiers",
        "Tags": "list:Tags",
    },
    "nat_gateways": {
        "NatGatewayId": "identifier",
        "VpcId": "identifier",
        "SubnetId": "identifier",
        "State": "enum:NatGatewayState",
        "ConnectivityType": "enum:ConnectivityType",
        "CreateTime": "timestamp",
        "Tags": "list:Tags",
    },
    "network_interfaces": {
        "NetworkInterfaceId": "identifier",
        "VpcId": "identifier",
        "SubnetId": "identifier",
        "InterfaceType": "enum:NetworkInterfaceType",
        "Description": "text",
        "RequesterManaged": "boolean",
        "Attachment": "object:Attachment",
        "Association": "object:Association",
        "TagSet": "list:Tags",
    },
    "addresses": {"AllocationId": "identifier", "AssociationId": "identifier", "PublicIp": "ip", "Tags": "list:Tags"},
    "transit_gateways": {"TransitGatewayId": "identifier", "Tags": "list:Tags"},
    "transit_gateway_attachments": {
        "TransitGatewayAttachmentId": "identifier",
        "TransitGatewayId": "identifier",
        "ResourceId": "identifier",
        "ResourceType": "enum:TransitGatewayAttachmentResourceType",
        "ResourceOwnerId": "account",
        "State": "enum:TransitGatewayAttachmentState",
        "Tags": "list:Tags",
    },
    "transit_gateway_route_tables": {"TransitGatewayRouteTableId": "identifier", "TransitGatewayId": "identifier", "Tags": "list:Tags"},
    "vpc_endpoint_service_configurations": {"ServiceId": "identifier", "ServiceName": "service", "Tags": "list:Tags"},
}
NESTED_FIELDS: dict[str, dict[str, str]] = {
    "Routes": {
        "DestinationCidrBlock": "cidr",
        "DestinationIpv6CidrBlock": "cidr",
        "DestinationPrefixListId": "identifier",
        "NatGatewayId": "identifier",
        "GatewayId": "gateway",
        "TransitGatewayId": "identifier",
        "VpcPeeringConnectionId": "identifier",
        "NetworkInterfaceId": "identifier",
        "State": "enum:RouteState",
        "Origin": "enum:RouteOrigin",
    },
    "Associations": {
        "SubnetId": "identifier",
        "Main": "boolean",
        "RouteTableAssociationId": "identifier",
        "RouteTableId": "identifier",
        "GatewayId": "gateway",
        "AssociationState": "object:AssociationState",
    },
    "Attachment": {"InstanceId": "identifier"},
    "Association": {"PublicIp": "ip", "AllocationId": "identifier"},
    "AssociationState": {"State": "enum:RouteTableAssociationStateCode"},
    "Tags": {"Key": "tag_key", "Value": "tag_value"},
}


@lru_cache(maxsize=16)
def enum_values(shape: str) -> frozenset[str]:
    """Read a named finite vocabulary from the installed SDK without AWS access."""
    value = Loader().load_service_model("ec2", "service-2")["shapes"][shape]["enum"]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        message = "Malformed local network provider vocabulary."
        raise ValueError(message)
    return frozenset(value)


class NetworkFactsPolicy:
    """Reject unknown facts per resource kind, including empty and null containers."""

    @classmethod
    def unknown_paths(cls, value: Any, resource_kind: object, path: str) -> list[str]:  # noqa: ANN401
        """Validate one actual projected facts object before any strict removal."""
        fields = RESOURCE_FIELDS.get(resource_kind) if isinstance(resource_kind, str) else None
        if fields is None:
            return [path]
        return cls._object_paths(value, fields, path)

    @classmethod
    def _object_paths(cls, value: Any, fields: dict[str, str], path: str) -> list[str]:  # noqa: ANN401
        if not isinstance(value, dict):
            return [path]
        failures = []
        for key, child in value.items():
            spec = fields.get(key)
            child_path = path + "." + str(key)
            failures.extend([child_path] if spec is None else cls._value_paths(child, spec, child_path))
        return failures

    @classmethod
    def _value_paths(cls, value: Any, spec: str, path: str) -> list[str]:  # noqa: ANN401

        if value is None:
            return []
        if spec.startswith("object:"):
            return cls._object_paths(value, NESTED_FIELDS[spec.removeprefix("object:")], path)
        if spec.startswith("list:"):
            if not isinstance(value, list):
                return [path]
            return [failure for child in value for failure in cls._object_paths(child, NESTED_FIELDS[spec.removeprefix("list:")], path + "[]")]
        if spec == "identifiers":
            return [] if isinstance(value, list) and all(isinstance(child, str) for child in value) else [path]
        if spec == "boolean":
            return [] if type(value) is bool else [path]
        return cls._string_paths(value, spec, path)

    @staticmethod
    def _string_paths(value: object, spec: str, path: str) -> list[str]:
        if not isinstance(value, str):
            return [path]
        if spec.startswith("enum:"):
            values = enum_values(spec.removeprefix("enum:"))

            valid = (
                value.casefold() in {item.casefold() for item in values}
                if spec in {"enum:State", "enum:TransitGatewayAttachmentResourceType", "enum:TransitGatewayAttachmentState"}
                else value in values
            )
            return [] if valid else [path]
        if spec == "timestamp":
            try:
                datetime.fromisoformat(value)
            except ValueError:
                return [path]
        return []
