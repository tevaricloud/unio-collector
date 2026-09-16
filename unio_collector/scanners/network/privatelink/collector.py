from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.network.bounds import PRIVATELINK_TOPOLOGY_BYTES, NetworkEvidenceBounds
from unio_collector.aws.network.projection import build_network_topology
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.network.privatelink.evidence import (
    PrivateLinkCostReviewEvidence,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.aws.network.inventory import NetworkInventoryCollector
    from unio_collector.scanners.scanner.context import ScannerContext


class NetworkPrivateLinkCostReviewCollector(BaseUnioScanner):
    """Collect network evidence without running finding interpretation."""

    def collect(self, context: ScannerContext) -> PrivateLinkCostReviewEvidence:  # noqa: D102
        def collect_service_configurations(
            collector: NetworkInventoryCollector,
        ) -> dict[str, list[dict[str, Any]]]:
            return collector.collect_vpc_endpoint_service_configurations_by_region()

        regions = context.network.get_regions()
        collector = context.network.create_collector(regions=regions)
        endpoints_by_region = context.network.collect_batch(
            collection_name="vpc_endpoints",
            label="VPC endpoint inventory",
            collect_items=(lambda collector: collector.collect_vpc_endpoints_by_region()),
        )
        service_configurations_by_region = context.network.collect_batch(
            collection_name="vpc_endpoint_service_configurations",
            label="VPC endpoint service configuration inventory",
            collect_items=collect_service_configurations,
        )
        records = collector.build_privatelink_region_records(
            endpoints_by_region=endpoints_by_region.as_dictionary(),
            service_configurations_by_region=service_configurations_by_region.as_dictionary(),
        )
        return PrivateLinkCostReviewEvidence(
            records=records,
            regions=collector.get_available_regions(),
            network_evidence_version="neutral-topology-v1",
            topology=build_network_topology(
                account_id=collector.account_id,
                regions=regions,
                batches=(
                    endpoints_by_region,
                    service_configurations_by_region,
                ),
                bounds=NetworkEvidenceBounds(PRIVATELINK_TOPOLOGY_BYTES),
            ),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="NetworkPrivateLinkCostReviewScanner",
            implementation_module="unio_collector.scanners.network.privatelink.scanner",
        )
