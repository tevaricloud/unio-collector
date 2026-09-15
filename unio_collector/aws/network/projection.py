"""Project provider inventory into bounded facts without opportunity inference."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING, Any

from unio_collector.aws.ec2.helpers import tags_to_dict
from unio_collector.aws.ec2.public_ipv4_record import PublicIpv4RegionRecord
from unio_collector.aws.network.bounds import NetworkEvidenceBounds
from unio_collector.aws.network.coverage import NetworkCollectionCoverage
from unio_collector.aws.network.resource import NetworkResourceFact
from unio_collector.aws.network.topology import NetworkTopologyEvidence
from unio_collector.aws.network.transit import NetworkTransitMixin

if TYPE_CHECKING:
    from unio_collector.aws.network.batch import NetworkInventoryBatch


RESOURCE_FIELDS: dict[str, tuple[str, ...]] = {
    "vpcs": ("VpcId", "Tags"),
    "subnets": ("SubnetId", "VpcId", "AvailabilityZone", "Tags"),
    "route_tables": ("RouteTableId", "VpcId", "Routes", "Associations", "Tags"),
    "vpc_endpoints": ("VpcEndpointId", "VpcId", "VpcEndpointType", "ServiceName", "State", "RouteTableIds", "SubnetIds", "Tags"),
    "nat_gateways": ("NatGatewayId", "VpcId", "SubnetId", "State", "ConnectivityType", "CreateTime", "Tags"),
    "network_interfaces": (
        "NetworkInterfaceId",
        "VpcId",
        "SubnetId",
        "InterfaceType",
        "Description",
        "RequesterManaged",
        "Attachment",
        "Association",
        "TagSet",
    ),
    "addresses": ("AllocationId", "AssociationId", "PublicIp", "Tags"),
    "transit_gateways": ("TransitGatewayId", "Tags"),
    "transit_gateway_attachments": ("TransitGatewayAttachmentId", "TransitGatewayId", "ResourceId", "ResourceType", "ResourceOwnerId", "State", "Tags"),
    "transit_gateway_route_tables": ("TransitGatewayRouteTableId", "TransitGatewayId", "Tags"),
    "vpc_endpoint_service_configurations": ("ServiceId", "ServiceName", "Tags"),
}
NESTED_FIELDS: dict[str, tuple[str, ...]] = {
    "Routes": (
        "DestinationCidrBlock",
        "DestinationIpv6CidrBlock",
        "DestinationPrefixListId",
        "NatGatewayId",
        "GatewayId",
        "TransitGatewayId",
        "VpcPeeringConnectionId",
        "NetworkInterfaceId",
        "State",
        "Origin",
    ),
    "Associations": ("SubnetId", "Main", "RouteTableAssociationId", "RouteTableId", "GatewayId", "AssociationState"),
    "Attachment": ("InstanceId",),
    "Association": ("PublicIp", "AllocationId"),
    "AssociationState": ("State",),
    "Tags": ("Key", "Value"),
    "TagSet": ("Key", "Value"),
}


def project_fields(item: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Copy declared provider fields, preserving nested observation order."""
    result: dict[str, Any] = {}
    for key in fields:
        if key not in item:
            continue
        value = item[key]
        nested = NESTED_FIELDS.get(key)
        if nested and isinstance(value, dict):
            value = project_fields(value, nested)
        elif nested and isinstance(value, list):
            value = [project_fields(child, nested) if isinstance(child, dict) else child for child in value]
        result[key] = value.isoformat() if isinstance(value, datetime) else value
    return result


def build_network_topology(
    *,
    account_id: str,
    regions: list[str],
    batches: tuple[NetworkInventoryBatch, ...],
    bounds: NetworkEvidenceBounds | None = None,
) -> list[NetworkTopologyEvidence]:
    """Join collection scope and facts; retain conflicting identities as ambiguous."""
    result = []
    for region in regions:
        resources: list[NetworkResourceFact] = []
        coverage: list[NetworkCollectionCoverage] = []
        ambiguous = False
        for batch in batches:
            matches = [item for item in batch.coverage if item.region == region]
            coverage.extend(
                matches
                or [
                    NetworkCollectionCoverage(
                        account_id,
                        batch.collection_name,
                        region,
                        "",
                        "skipped",
                        reason_codes=("not_collected",),
                    )
                ]
            )
            if batch.account_id != account_id or len(matches) != 1:
                ambiguous = True
            fields = RESOURCE_FIELDS[batch.collection_name]
            seen: dict[str, int] = {}
            for ordinal, item in enumerate(batch.items_by_region.get(region, [])):
                facts = project_fields(item, fields)
                identity = str(facts.get(fields[0]) or "")
                if not identity:
                    identity = str(facts.get("PublicIp") or facts.get("ServiceName") or "")
                if not identity:
                    ambiguous = True
                if identity in seen:
                    previous = resources[seen[identity]]
                    if previous.facts == facts:
                        resources[seen[identity]] = replace(previous, repeated_observation_ordinals=(*previous.repeated_observation_ordinals, ordinal))
                        continue
                    ambiguous = True
                seen[identity] = len(resources)
                resources.append(NetworkResourceFact(batch.collection_name, identity, ordinal, facts))
        ambiguous = ambiguous or conflicting_associations(resources)
        evidence = NetworkTopologyEvidence(
            account_id,
            region,
            tuple(resources),
            tuple(coverage),
            relation_state="ambiguous" if ambiguous else "complete",
            reason_codes=("topology_relation_unresolved",) if ambiguous else (),
        )
        result.append((bounds or NetworkEvidenceBounds()).apply(evidence))
    return result


def conflicting_associations(resources: list[NetworkResourceFact]) -> bool:
    """Detect multiple observed route tables assigned to one subnet or VPC main."""
    owners: dict[tuple[str, str], str] = {}
    for resource in resources:
        if resource.kind != "route_tables":
            continue
        for association in resource.facts.get("Associations") or []:
            if not isinstance(association, dict):
                continue
            keys = []
            if association.get("SubnetId"):
                keys.append(("subnet", str(association["SubnetId"])))
            if association.get("Main"):
                keys.append(("main", str(resource.facts.get("VpcId", ""))))
            for key in keys:
                if key in owners and owners[key] != resource.identity:
                    return True
                owners[key] = resource.identity
    return False


class NetworkTopologyProjection(NetworkTransitMixin):
    """Reduce neutral evidence to the existing factual summaries without AWS access."""

    def __init__(self, account_id: str) -> None:
        """Bind the observed account identity."""
        self.account_id = account_id

    def build_public_ipv4_region_record(
        self,
        *,
        region: str,
        addresses: list[dict[str, Any]],
        interfaces: list[dict[str, Any]],
    ) -> PublicIpv4RegionRecord:
        """Project factual regional counts and historical observation-order samples."""
        allocation_ids = [str(address.get("AllocationId")) for address in addresses if address.get("AllocationId")]
        tagged_address_count = sum(1 for address in addresses if tags_to_dict(address.get("Tags", [])))
        attached_allocation_ids = {str(address.get("AllocationId")) for address in addresses if address.get("AllocationId") and address.get("AssociationId")}
        eni_public_ips = [interface for interface in interfaces if interface.get("Association", {}).get("PublicIp")]
        auto_assigned_public_ip_count = sum(1 for interface in eni_public_ips if not interface.get("Association", {}).get("AllocationId"))
        return PublicIpv4RegionRecord(
            account_id=self.account_id,
            region=region,
            elastic_ip_count=len(addresses),
            attached_elastic_ip_count=len(attached_allocation_ids),
            unattached_elastic_ip_count=max(
                0,
                len(addresses) - len(attached_allocation_ids),
            ),
            eni_public_ip_count=len(eni_public_ips),
            auto_assigned_public_ip_count=auto_assigned_public_ip_count,
            allocation_ids=allocation_ids[:25],
            sample_interface_ids=[str(interface.get("NetworkInterfaceId")) for interface in eni_public_ips[:25] if interface.get("NetworkInterfaceId")],
            tagged_address_count=tagged_address_count,
        )

    def _count_items(self, items: list[str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in items:
            counts[item] = counts.get(item, 0) + 1
        return dict(sorted(counts.items()))
