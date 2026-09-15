"""Network inventory public exports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = [
    "COMMON_INTERFACE_ENDPOINT_SERVICE_SUFFIXES",
    "NatGatewayRecord",
    "NetworkInventoryCollector",
    "NetworkRegionItems",
    "PrivateLinkRegionRecord",
    "PublicIpv4RegionRecord",
    "TransitGatewayRegionRecord",
    "VpcEndpointVpcRecord",
]

_EXPORT_MODULES = {
    "COMMON_INTERFACE_ENDPOINT_SERVICE_SUFFIXES": "unio_collector.aws.network.collector",
    "NatGatewayRecord": "unio_collector.aws.network.nat_gateway_record",
    "NetworkInventoryCollector": "unio_collector.aws.network.collector",
    "NetworkRegionItems": "unio_collector.aws.network.region_items",
    "PrivateLinkRegionRecord": "unio_collector.aws.network.private_link_record",
    "PublicIpv4RegionRecord": "unio_collector.aws.ec2.public_ipv4_record",
    "TransitGatewayRegionRecord": "unio_collector.aws.network.transit_gateway_record",
    "VpcEndpointVpcRecord": "unio_collector.aws.network.vpc_endpoint_record",
}

if TYPE_CHECKING:
    from unio_collector.aws.ec2.public_ipv4_record import PublicIpv4RegionRecord
    from unio_collector.aws.network.collector import (
        COMMON_INTERFACE_ENDPOINT_SERVICE_SUFFIXES,
        NetworkInventoryCollector,
    )
    from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
    from unio_collector.aws.network.private_link_record import PrivateLinkRegionRecord
    from unio_collector.aws.network.region_items import NetworkRegionItems
    from unio_collector.aws.network.transit_gateway_record import TransitGatewayRegionRecord
    from unio_collector.aws.network.vpc_endpoint_record import VpcEndpointVpcRecord


def __getattr__(name: str) -> Any:  # noqa: ANN401
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    module = __import__(module_name, fromlist=[name])
    return getattr(module, name)
