"""Neutral route facts without destination-specific path inference."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FlowRouteRecord:
    """An observed route and its table provenance, never a selected traffic path."""

    route_table_id: str
    vpc_id: str | None
    destination: str | None
    address_family: str
    state: str | None
    origin: str | None
    targets: tuple[tuple[str, str], ...]
    associations: tuple[tuple[str, str], ...]

    @classmethod
    def from_response(cls, table: dict[str, Any], route: dict[str, Any]) -> FlowRouteRecord:
        """Retain route targets and explicit/main association facts."""
        target_keys = (
            "NatGatewayId",
            "GatewayId",
            "TransitGatewayId",
            "VpcPeeringConnectionId",
            "NetworkInterfaceId",
            "InstanceId",
            "EgressOnlyInternetGatewayId",
            "LocalGatewayId",
            "CarrierGatewayId",
            "CoreNetworkArn",
        )
        associations = tuple(
            sorted(
                (str(item.get("SubnetId") or ""), "main_vpc" if item.get("Main") else "explicit_subnet")
                for item in table.get("Associations", [])
                if item.get("Main") or item.get("SubnetId")
            )
        )
        return cls(
            route_table_id=str(table.get("RouteTableId") or ""),
            vpc_id=table.get("VpcId"),
            destination=route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock") or route.get("DestinationPrefixListId"),
            address_family="ipv4" if route.get("DestinationCidrBlock") else "ipv6" if route.get("DestinationIpv6CidrBlock") else "prefix_list",
            state=route.get("State"),
            origin=route.get("Origin"),
            targets=tuple((key, str(route[key])) for key in target_keys if route.get(key)),
            associations=associations,
        )
