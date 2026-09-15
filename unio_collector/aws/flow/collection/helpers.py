from __future__ import annotations  # noqa: D100

import ipaddress
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from unio_collector.aws.inventory_helpers import AwsInventoryValueHelper
from unio_collector.aws.route_table_context import RouteTableContext

if TYPE_CHECKING:
    from unio_collector.aws.flow.observation import FlowObservation

FLOW_LOG_INSIGHTS_QUERY_TEMPLATE = """
fields @message
| parse @message "* * * * * * * * * * * * * *" as version, accountId, interfaceId, srcaddr, dstaddr, srcport, dstport, protocol, packetCount, byteCount, startEpoch, endEpoch, action, logStatus
| filter action = "ACCEPT"
| stats sum(byteCount) as totalBytes, sum(packetCount) as totalPackets, count(*) as flowCount by srcaddr, dstaddr, action
| sort totalBytes desc, srcaddr asc, dstaddr asc, action asc
| limit {query_limit}
""".strip()  # noqa: E501

ATTRIBUTION_TAG_KEYS = {
    "Name",
    "Owner",
    "Team",
    "Project",
    "Application",
    "Service",
    "Environment",
    "CostCentre",
    "CostCenter",
    "BusinessUnit",
}


def build_flow_log_insights_query(query_limit: int) -> str:  # noqa: D103
    return FLOW_LOG_INSIGHTS_QUERY_TEMPLATE.format(query_limit=max(1, query_limit))


def parse_ip_address(  # noqa: D103
    value: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_private_ip(value: str) -> bool:  # noqa: D103
    parsed = parse_ip_address(value)
    return bool(parsed and parsed.is_private)


def chunked(values: list[str], size: int) -> list[list[str]]:  # noqa: D103
    return AwsInventoryValueHelper().chunk_values(values, size)


def build_network_interface_context(interface: dict[str, Any]) -> dict[str, Any]:  # noqa: D103
    attachment = interface.get("Attachment") or {}
    return {
        "eni_id": interface.get("NetworkInterfaceId"),
        "resource_owner_id": interface.get("OwnerId"),
        "vpc_id": interface.get("VpcId"),
        "subnet_id": interface.get("SubnetId"),
        "availability_zone": interface.get("AvailabilityZone"),
        "description": interface.get("Description"),
        "interface_type": interface.get("InterfaceType"),
        "attachment_instance_id": attachment.get("InstanceId"),
        "private_dns_name": interface.get("PrivateDnsName"),
        "attribution_tags": select_attribution_tags(interface.get("TagSet", [])),
    }


def select_attribution_tags(tags: list[dict[str, Any]]) -> dict[str, str]:  # noqa: D103
    selected: dict[str, str] = {}
    for tag in tags:
        key = str(tag.get("Key") or "")
        value = tag.get("Value")
        if key in ATTRIBUTION_TAG_KEYS and value not in (None, ""):
            selected[key] = str(value)
    return selected


def enrich_record_with_interface_context(  # noqa: D103
    record: FlowObservation,
    eni_by_ip: dict[str, dict[str, Any]],
) -> FlowObservation:
    src = eni_by_ip.get(record.srcaddr, {})
    dst = eni_by_ip.get(record.dstaddr, {})
    statuses = {}
    if hasattr(record, "src_address_status"):
        statuses = {
            "src_address_status": src.get("address_status")
            or ("resolved_uniquely" if src.get("eni_id") else "unresolved" if is_private_ip(record.srcaddr) else "not_attempted"),
            "dst_address_status": dst.get("address_status")
            or ("resolved_uniquely" if dst.get("eni_id") else "unresolved" if is_private_ip(record.dstaddr) else "not_attempted"),
        }
    return replace(
        record,
        **statuses,
        src_eni_id=src.get("eni_id"),
        src_resource_owner_id=src.get("resource_owner_id"),
        src_vpc_id=src.get("vpc_id"),
        src_subnet_id=src.get("subnet_id"),
        src_availability_zone=src.get("availability_zone"),
        src_description=src.get("description"),
        src_interface_type=src.get("interface_type"),
        src_attachment_instance_id=src.get("attachment_instance_id"),
        src_private_dns_name=src.get("private_dns_name"),
        src_attribution_tags=src.get("attribution_tags"),
        dst_eni_id=dst.get("eni_id"),
        dst_resource_owner_id=dst.get("resource_owner_id"),
        dst_vpc_id=dst.get("vpc_id"),
        dst_subnet_id=dst.get("subnet_id"),
        dst_availability_zone=dst.get("availability_zone"),
        dst_description=dst.get("description"),
        dst_interface_type=dst.get("interface_type"),
        dst_attachment_instance_id=dst.get("attachment_instance_id"),
        dst_private_dns_name=dst.get("private_dns_name"),
        dst_attribution_tags=dst.get("attribution_tags"),
    )


def build_subnet_route_table_contexts(  # noqa: D103
    route_table: dict[str, Any],
) -> list[tuple[str, RouteTableContext]]:
    contexts: list[tuple[str, RouteTableContext]] = []
    for association in route_table.get("Associations", []):
        subnet_id = association.get("SubnetId")
        if not subnet_id:
            continue
        contexts.append(
            (
                subnet_id,
                build_route_table_context(
                    route_table,
                    subnet_id=subnet_id,
                    association="explicit_subnet",
                ),
            ),
        )
    return contexts


def build_main_route_table_context(route_table: dict[str, Any]) -> RouteTableContext:  # noqa: D103
    return build_route_table_context(
        route_table,
        subnet_id=None,
        association="main_vpc",
    )


def build_route_table_context(  # noqa: D103
    route_table: dict[str, Any],
    *,
    subnet_id: str | None,
    association: str,
) -> RouteTableContext:
    target, target_type = find_default_route_target(route_table.get("Routes", []))
    return RouteTableContext(
        route_table_id=route_table.get("RouteTableId"),
        vpc_id=route_table.get("VpcId"),
        subnet_id=subnet_id,
        default_route_target=target,
        default_route_target_type=target_type,
        association=association,
    )


def find_default_route_target(  # noqa: D103
    routes: list[dict[str, Any]],
) -> tuple[str | None, str | None]:
    for route in routes:
        destination = route.get("DestinationCidrBlock") or route.get(
            "DestinationIpv6CidrBlock",
        )
        if destination not in {"0.0.0.0/0", "::/0"}:
            continue
        return extract_route_target(route)
    return None, None


def extract_route_target(route: dict[str, Any]) -> tuple[str | None, str | None]:  # noqa: D103
    route_target_fields = (
        ("NatGatewayId", "nat_gateway"),
        ("GatewayId", "gateway"),
        ("TransitGatewayId", "transit_gateway"),
        ("VpcPeeringConnectionId", "vpc_peering"),
        ("NetworkInterfaceId", "network_interface"),
        ("InstanceId", "instance"),
        ("EgressOnlyInternetGatewayId", "egress_only_internet_gateway"),
        ("LocalGatewayId", "local_gateway"),
        ("CarrierGatewayId", "carrier_gateway"),
    )
    for field, target_type in route_target_fields:
        value = route.get(field)
        if value:
            if field == "GatewayId" and str(value).startswith("igw-"):
                return str(value), "internet_gateway"
            return str(value), target_type
    return None, None


def enrich_record_with_route_context(  # noqa: D103
    record: FlowObservation,
    subnet_routes: dict[str, RouteTableContext],
    main_routes: dict[str, RouteTableContext],
) -> FlowObservation:
    src_route = lookup_route_context(
        record.src_subnet_id,
        record.src_vpc_id,
        subnet_routes,
        main_routes,
    )
    dst_route = lookup_route_context(
        record.dst_subnet_id,
        record.dst_vpc_id,
        subnet_routes,
        main_routes,
    )
    return replace(
        record,
        src_route_table_id=getattr(src_route, "route_table_id", None),
        src_default_route_target=getattr(src_route, "default_route_target", None),
        src_default_route_target_type=getattr(
            src_route,
            "default_route_target_type",
            None,
        ),
        src_route_table_association=getattr(src_route, "association", None),
        dst_route_table_id=getattr(dst_route, "route_table_id", None),
        dst_default_route_target=getattr(dst_route, "default_route_target", None),
        dst_default_route_target_type=getattr(
            dst_route,
            "default_route_target_type",
            None,
        ),
        dst_route_table_association=getattr(dst_route, "association", None),
    )


def lookup_route_context(  # noqa: D103
    subnet_id: str | None,
    vpc_id: str | None,
    subnet_routes: dict[str, RouteTableContext],
    main_routes: dict[str, RouteTableContext],
) -> RouteTableContext | None:
    if subnet_id and subnet_id in subnet_routes:
        return subnet_routes[subnet_id]
    if vpc_id:
        return main_routes.get(vpc_id)
    return None
