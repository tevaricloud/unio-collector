from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scanners.inventory_evidence import InventoryEvidence

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


from unio_collector.scanners.ec2.inventory.collector import CachedEc2InventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class NatGatewayInventoryCollector(CachedEc2InventoryCollector):
    """Collect provider evidence for nat-gateway-inventory."""

    collection_name = "nat_gateways"

    def collect(self, context: ScannerContext) -> InventoryEvidence:  # noqa: D102
        return InventoryEvidence(
            records=context.network.collect_nat_gateway_records(),
            regions=context.network.get_regions(),
        )

    def collect_records(self, collector: Any) -> list[Any]:  # noqa: ANN401, D102
        return collector.collect_nat_gateways()

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="NatGatewayInventoryScanner",
            implementation_module="unio_collector.scanners.network.nat_gateway.inventory_scanner",
        )
