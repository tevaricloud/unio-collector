from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.network.bounds import TRANSIT_TOPOLOGY_BYTES, NetworkEvidenceBounds
from unio_collector.aws.network.inventory import NetworkInventoryCollector
from unio_collector.aws.network.projection import build_network_topology
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.network.transit_gateway.evidence import (
    TransitGatewayCostReviewEvidence,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class NetworkTransitGatewayCostReviewCollector(BaseUnioScanner):
    """Collect network evidence without running finding interpretation."""

    def collect(self, context: ScannerContext) -> TransitGatewayCostReviewEvidence:  # noqa: D102
        collector = context.security.create_regional_inventory_collector(
            NetworkInventoryCollector,
            collector_name="NetworkInventoryCollector",
        )
        records = collector.collect_transit_gateway_region_records()
        return TransitGatewayCostReviewEvidence(
            records=records,
            network_evidence_version="neutral-topology-v1",
            topology=build_network_topology(
                account_id=collector.account_id,
                regions=collector.get_available_regions(),
                batches=collector.collected_batches(),
                bounds=NetworkEvidenceBounds(TRANSIT_TOPOLOGY_BYTES),
            ),
            regions=collector.get_available_regions(),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="NetworkTransitGatewayCostReviewScanner",
            implementation_module="unio_collector.scanners.network.transit_gateway.scanner",
        )
