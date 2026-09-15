# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import Any

from unio_collector.aws.ec2.helpers import tags_to_dict
from unio_collector.aws.network.private_link_record import PrivateLinkRegionRecord
from unio_collector.aws.network.transit_gateway_record import TransitGatewayRegionRecord


class NetworkTransitMixin:  # noqa: D101
    def build_transit_gateway_region_record(
        self,
        *,
        region: str,
        gateways: list[dict[str, Any]],
        attachments: list[dict[str, Any]],
        route_tables: list[dict[str, Any]],
    ) -> list[TransitGatewayRegionRecord]:
        """Project factual regional counts and historical observation-order samples."""
        active_attachments = [attachment for attachment in attachments if str(attachment.get("State") or "").lower() in {"available", "pending", "modifying"}]
        active_resource_types = [str(attachment.get("ResourceType") or "unknown").lower() for attachment in active_attachments]
        return [
            TransitGatewayRegionRecord(
                account_id=self.account_id,
                region=region,
                transit_gateway_count=len(gateways),
                attachment_count=len(attachments),
                active_attachment_count=len(active_attachments),
                active_vpc_attachment_count=active_resource_types.count("vpc"),
                active_vpn_attachment_count=active_resource_types.count("vpn"),
                active_peering_attachment_count=active_resource_types.count("peering"),
                active_direct_connect_attachment_count=active_resource_types.count(
                    "direct-connect-gateway",
                ),
                active_connect_attachment_count=active_resource_types.count("connect"),
                cross_account_attachment_count=sum(
                    1 for attachment in active_attachments if attachment.get("ResourceOwnerId") and str(attachment.get("ResourceOwnerId")) != self.account_id
                ),
                route_table_count=len(route_tables),
                tagged_transit_gateway_count=sum(1 for gateway in gateways if tags_to_dict(gateway.get("Tags", []))),
                tagged_attachment_count=sum(1 for attachment in active_attachments if tags_to_dict(attachment.get("Tags", []))),
                untagged_transit_gateway_count=sum(1 for gateway in gateways if not tags_to_dict(gateway.get("Tags", []))),
                untagged_active_attachment_count=sum(1 for attachment in active_attachments if not tags_to_dict(attachment.get("Tags", []))),
                attachment_resource_type_counts=self._count_items(
                    active_resource_types,
                ),
                sample_transit_gateway_ids=[str(gateway.get("TransitGatewayId")) for gateway in gateways[:10] if gateway.get("TransitGatewayId")],
                sample_attachment_ids=[
                    str(attachment.get("TransitGatewayAttachmentId")) for attachment in attachments[:10] if attachment.get("TransitGatewayAttachmentId")
                ],
                sample_cross_account_attachment_ids=[
                    str(attachment.get("TransitGatewayAttachmentId"))
                    for attachment in active_attachments[:10]
                    if attachment.get("TransitGatewayAttachmentId")
                    and attachment.get("ResourceOwnerId")
                    and str(attachment.get("ResourceOwnerId")) != self.account_id
                ],
                sample_route_table_ids=[
                    str(route_table.get("TransitGatewayRouteTableId")) for route_table in route_tables[:10] if route_table.get("TransitGatewayRouteTableId")
                ],
                sample_attachment_resource_types=sorted(set(active_resource_types))[:10],
            ),
        ]

    def build_privatelink_region_record(
        self,
        *,
        region: str,
        endpoints: list[dict[str, Any]],
        service_configurations: list[dict[str, Any]],
    ) -> list[PrivateLinkRegionRecord]:
        """Project factual regional counts and historical observation-order samples."""
        interface_endpoints = [endpoint for endpoint in endpoints if endpoint.get("VpcEndpointType") == "Interface"]
        gateway_load_balancer_endpoints = [endpoint for endpoint in endpoints if endpoint.get("VpcEndpointType") == "GatewayLoadBalancer"]
        private_link_endpoints = [
            *interface_endpoints,
            *gateway_load_balancer_endpoints,
        ]
        available_endpoints = [endpoint for endpoint in private_link_endpoints if str(endpoint.get("State") or "").lower() == "available"]
        pending_endpoints = [endpoint for endpoint in private_link_endpoints if str(endpoint.get("State") or "").lower() in {"pending", "pendingacceptance"}]
        service_names = sorted(
            {str(endpoint.get("ServiceName")) for endpoint in private_link_endpoints if endpoint.get("ServiceName")},
        )
        endpoint_service_names = sorted(
            {str(configuration.get("ServiceName")) for configuration in service_configurations if configuration.get("ServiceName")},
        )
        return [
            PrivateLinkRegionRecord(
                account_id=self.account_id,
                region=region,
                interface_endpoint_count=len(interface_endpoints),
                gateway_load_balancer_endpoint_count=(len(gateway_load_balancer_endpoints)),
                available_endpoint_count=len(available_endpoints),
                pending_endpoint_count=len(pending_endpoints),
                tagged_endpoint_count=sum(1 for endpoint in private_link_endpoints if tags_to_dict(endpoint.get("Tags", []))),
                endpoint_service_count=len(service_configurations),
                endpoint_service_names=endpoint_service_names[:25],
                sample_endpoint_ids=[str(endpoint.get("VpcEndpointId")) for endpoint in private_link_endpoints[:25] if endpoint.get("VpcEndpointId")],
                sample_vpc_ids=sorted(
                    {str(endpoint.get("VpcId")) for endpoint in private_link_endpoints if endpoint.get("VpcId")},
                )[:25],
                sample_service_names=service_names[:25],
            ),
        ]
