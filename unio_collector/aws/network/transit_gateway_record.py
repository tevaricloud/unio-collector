from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TransitGatewayRegionRecord:  # noqa: D101
    account_id: str
    region: str
    transit_gateway_count: int = 0
    attachment_count: int = 0
    active_attachment_count: int = 0
    active_vpc_attachment_count: int = 0
    active_vpn_attachment_count: int = 0
    active_peering_attachment_count: int = 0
    active_direct_connect_attachment_count: int = 0
    active_connect_attachment_count: int = 0
    cross_account_attachment_count: int = 0
    route_table_count: int = 0
    tagged_transit_gateway_count: int = 0
    tagged_attachment_count: int = 0
    untagged_transit_gateway_count: int = 0
    untagged_active_attachment_count: int = 0
    attachment_resource_type_counts: dict[str, int] = field(default_factory=dict)
    sample_transit_gateway_ids: list[str] = field(default_factory=list)
    sample_attachment_ids: list[str] = field(default_factory=list)
    sample_cross_account_attachment_ids: list[str] = field(default_factory=list)
    sample_route_table_ids: list[str] = field(default_factory=list)
    sample_attachment_resource_types: list[str] = field(default_factory=list)
