"""Actual six-kind VPC endpoint producer with synthetic routes and relationships."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from tools.collector_ipv4_fixture import VARIANTS as BASE_VARIANTS
from tools.collector_privatelink_fixture import SyntheticPrivateLinkSession
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.network.inventory import NetworkInventoryCollector
from unio_collector.scanners.network.vpc_endpoint.collector import NetworkVpcEndpointOpportunityReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "network-vpc-endpoint-opportunity-review"
VARIANTS = (*BASE_VARIANTS, "gateway_covered", "descriptions")


class SyntheticVpcSession(SyntheticPrivateLinkSession):
    """Exercise all projected route/association fields without an SDK session."""

    def describe_vpc_endpoints(self, **kwargs: object) -> dict[str, Any]:
        """Exercise both covered gateway routes and missing service coverage."""
        if self.variant == "gateway_covered":
            rows = [
                {
                    "VpcEndpointId": "vpce-" + sentinel,
                    "VpcId": "vpc-00000000000000000",
                    "VpcEndpointType": "Gateway",
                    "ServiceName": "com.amazonaws.eu-west-2." + service,
                    "State": "Available",
                    "RouteTableIds": ["rtb-00000000000000000"],
                    "SubnetIds": [],
                    "Tags": [],
                }
                for service, sentinel in (("s3", "00000000000000000"), ("dynamodb", "fffffffffffffffff"))
            ]
            return self._response("VpcEndpoints", rows, kwargs)
        return super().describe_vpc_endpoints(**kwargs)

    def describe_network_interfaces(self, **kwargs: object) -> dict[str, Any]:
        """Expose the privacy-required loss of description-only workload attribution."""
        if self.variant == "descriptions":
            rows = [
                {
                    "NetworkInterfaceId": "eni-" + sentinel,
                    "VpcId": "vpc-00000000000000000",
                    "SubnetId": "subnet-00000000000000000",
                    "InterfaceType": "interface",
                    "Description": description,
                    "Attachment": {},
                    "RequesterManaged": False,
                    "TagSet": [],
                }
                for description, sentinel in (("amazon rds", "00000000000000000"), ("lambda", "fffffffffffffffff"))
            ]
            return self._response("NetworkInterfaces", rows, kwargs)
        return super().describe_network_interfaces(**kwargs)

    def describe_vpcs(self, **kwargs: object) -> dict[str, Any]:
        """Return VPC identity and customer-owned tags."""
        row = {"VpcId": "vpc-00000000000000000", "Tags": [{"Key": "Name", "Value": "synthetic-customer-network"}]}
        if self.variant == "missing_id":
            row.pop("VpcId")
        return self._response("Vpcs", [row], kwargs)

    def describe_subnets(self, **kwargs: object) -> dict[str, Any]:
        """Populate explicit and inferred subnet scope including availability zones."""
        rows = [
            {"SubnetId": "subnet-" + sentinel, "VpcId": "vpc-00000000000000000", "AvailabilityZone": "eu-west-2a", "Tags": []}
            for sentinel in ("00000000000000000", "fffffffffffffffff")
        ]
        if self.variant == "optional":
            rows[0]["AvailabilityZone"] = None
        return self._response("Subnets", rows, kwargs)

    def describe_nat_gateways(self, **kwargs: object) -> dict[str, Any]:
        """Populate the route target and provider timestamp with deterministic sentinel IDs."""
        row = {
            "NatGatewayId": "nat-00000000000000000",
            "VpcId": "vpc-00000000000000000",
            "SubnetId": "subnet-00000000000000000",
            "State": "available",
            "ConnectivityType": "public",
            "CreateTime": datetime(2026, 9, 1, tzinfo=UTC),
            "Tags": [{"Key": "Owner", "Value": "synthetic-customer"}],
        }
        if self.variant == "optional":
            row.update(CreateTime=None, ConnectivityType=None)
        return self._response("NatGateways", [row], kwargs)

    def describe_route_tables(self, **kwargs: object) -> dict[str, Any]:
        """Keep finite route states, sources and nested association states populated."""
        routes: list[dict[str, Any]] = [
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-00000000000000000", "State": "active", "Origin": "CreateRoute"},
            {"DestinationIpv6CidrBlock": "::/0", "GatewayId": "local", "State": "active", "Origin": "CreateRouteTable"},
            {
                "DestinationPrefixListId": "pl-00000000000000000",
                "TransitGatewayId": "tgw-00000000000000000",
                "VpcPeeringConnectionId": "pcx-00000000000000000",
                "NetworkInterfaceId": "eni-00000000000000000",
                "State": "blackhole",
                "Origin": "EnableVgwRoutePropagation",
            },
        ]
        associations = [
            {
                "SubnetId": "subnet-00000000000000000",
                "Main": False,
                "RouteTableAssociationId": "rtbassoc-00000000000000000",
                "RouteTableId": "rtb-00000000000000000",
                "GatewayId": "igw-00000000000000000",
                "AssociationState": {"State": "associated"},
            },
            {"Main": True},
        ]
        if self.variant == "optional":
            routes[2].update(TransitGatewayId=None, VpcPeeringConnectionId=None, NetworkInterfaceId=None)
            associations[0]["AssociationState"] = None
        row = {
            "RouteTableId": "rtb-00000000000000000",
            "VpcId": "vpc-00000000000000000",
            "Routes": routes,
            "Associations": associations,
            "Tags": [{"Key": "Owner", "Value": "synthetic-customer"}],
        }
        return self._response("RouteTables", [row], kwargs)


def vpc_producer_case(variant: str = "success") -> dict[str, Any]:
    """Invoke the actual wrapper, network gateway, collection, projection and serializer."""
    if variant not in VARIANTS:
        message = "Unknown synthetic VPC endpoint variant."
        raise ValueError(message)
    session = SyntheticVpcSession(variant)
    definition: Any = SimpleNamespace(scanner_id=SCANNER)
    audit = AwsAuditContext(scanner_id=SCANNER, collector="NetworkInventoryCollector", allowed_api_calls=())
    collector = NetworkInventoryCollector(session, account_id="123456789012", audit_context=audit, selected_regions=["eu-west-2"])
    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(account_id="123456789012"),
        get_cached_network_regions=lambda _d: ["eu-west-2"],
        create_network_collector=lambda *_args, **_kwargs: collector,
        collect_cached_network_batch=lambda _d, collection_name, **_kwargs: collector.collect_inventory_batch(collection_name),
    )
    evidence = NetworkVpcEndpointOpportunityReviewCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)))


def add_vpc_producer_payload(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Add populated current VPC endpoint branches to the existing native fixture."""
    row = vpc_producer_case()
    if unknown:
        row["payload"]["topology"][0]["resources"][0]["facts"]["unknown_vpc_container"] = {}
    add_scanner_producer_payload(files, row)
