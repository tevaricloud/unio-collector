from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.network.projection import build_network_topology
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.network.vpc_endpoint.evidence import (
    VpcEndpointOpportunityEvidence,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class NetworkVpcEndpointOpportunityReviewCollector(BaseUnioScanner):
    """Collect network evidence without running finding interpretation."""

    def collect(self, context: ScannerContext) -> VpcEndpointOpportunityEvidence[object]:  # noqa: D102
        regions = context.network.get_regions()
        collector = context.network.create_collector(regions=regions)
        vpcs_by_region = context.network.collect_batch(
            collection_name="vpcs",
            label="EC2 VPC inventory",
            collect_items=(lambda collector: collector.collect_vpcs_by_region()),
        )
        route_tables_by_region = context.network.collect_batch(
            collection_name="route_tables",
            label="EC2 route table inventory",
            collect_items=(lambda collector: collector.collect_route_tables_by_region()),
        )
        endpoints_by_region = context.network.collect_batch(
            collection_name="vpc_endpoints",
            label="VPC endpoint inventory",
            collect_items=(lambda collector: collector.collect_vpc_endpoints_by_region()),
        )
        nat_gateways_by_region = context.network.collect_batch(
            collection_name="nat_gateways",
            label="NAT Gateway inventory",
            collect_items=(lambda collector: collector.collect_nat_gateways_by_region()),
        )
        interfaces_by_region = context.network.collect_batch(
            collection_name="network_interfaces",
            label="EC2 network interface inventory",
            collect_items=(lambda collector: collector.collect_network_interfaces_by_region()),
        )
        subnets_by_region = context.network.collect_batch(
            collection_name="subnets",
            label="EC2 subnet inventory",
            collect_items=lambda collector: collector.collect_subnets_by_region(),
        )
        return VpcEndpointOpportunityEvidence(
            records=[],
            regions=collector.get_available_regions(),
            network_evidence_version="neutral-topology-v1",
            topology=build_network_topology(
                account_id=collector.account_id,
                regions=regions,
                batches=(
                    vpcs_by_region,
                    route_tables_by_region,
                    endpoints_by_region,
                    nat_gateways_by_region,
                    interfaces_by_region,
                    subnets_by_region,
                ),
            ),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="NetworkVpcEndpointOpportunityReviewScanner",
            implementation_module="unio_collector.scanners.network.vpc_endpoint.scanner",
        )
