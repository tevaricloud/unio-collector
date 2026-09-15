from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.scanners.ec2.inventory.collector import CachedEc2InventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class UnassociatedElasticIpCollector(CachedEc2InventoryCollector):
    """Collect provider evidence for ec2-unassociated-elastic-ips."""

    collection_name = "unused_elastic_ips"

    def collect_records(self, collector: Any) -> list[Any]:  # noqa: ANN401, D102
        return collector.collect_unused_elastic_ips()

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="UnassociatedElasticIpScanner",
            implementation_module="unio_collector.scanners.ec2.elastic_ip.unassociated",
        )
