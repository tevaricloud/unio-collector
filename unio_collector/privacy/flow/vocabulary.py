"""Finite source-declared flow vocabularies and pinned offline SDK regions/enums."""

from botocore.loaders import create_loader

from unio_collector.aws.flow.limitations import FLOW_REASON_CODES, NOT_RETAINED_FIELDS
from unio_collector.privacy.network.facts import enum_values

REGIONS = frozenset(region for partition in create_loader().load_data("endpoints")["partitions"] for region in partition["regions"])
TARGET_KEYS = frozenset(
    {
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
    }
)
VOCABULARIES = {
    "flow_version": {"neutral-pairs-v1"},
    "flow_action": {"ACCEPT", "REJECT"},
    "address_status": {"not_attempted", "resolved_uniquely", "unresolved", "ambiguous"},
    "association": {"main_vpc", "explicit_subnet"},
    "target_type": {
        "nat_gateway",
        "internet_gateway",
        "egress_only_internet_gateway",
        "transit_gateway",
        "vpc_peering",
        "network_interface",
        "instance",
        "local_gateway",
        "carrier_gateway",
        "gateway",
    },
    "collection_state": {"complete", "partial", "unavailable", "capped", "skipped"},
    "query_state": {"complete", "partial", "capped", "unavailable"},
    "topology_state": {"complete", "partial", "unavailable", "ambiguous"},
    "reason": FLOW_REASON_CODES,
    "not_retained": frozenset(NOT_RETAINED_FIELDS),
    "retention_reason": {"fields_not_retained_by_pair_aggregation"},
    "format_scope": {"default-vpc-flow-log-fields"},
    "query_selection": {"bytes-desc-address-action-asc-v1"},
    "grouping_name": {"srcaddr", "dstaddr", "action"},
    "action_filter": {"ACCEPT"},
    "topology_selection": {"canonical-json-ascending-v1"},
    "route_scope": {"observed-default-context-not-destination-path"},
    "record_kind": {"route", "interface"},
    "route_kind": {"route"},
    "interface_kind": {"interface"},
    "address_family": {"ipv4", "ipv6", "prefix_list"},
    "target_key": TARGET_KEYS,
    "route_state": enum_values("RouteState"),
    "route_origin": enum_values("RouteOrigin"),
    "interface_type": enum_values("NetworkInterfaceType"),
    "period_kind": {"days", "months", "years", "date_range"},
}
