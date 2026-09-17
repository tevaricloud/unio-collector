from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.scanners.ec2.inventory.collector import CachedEc2InventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class UnattachedEbsVolumeCollector(CachedEc2InventoryCollector):
    """Collect provider evidence for ec2-unattached-ebs-volumes."""

    collection_name = "unattached_volumes"

    def collect_records(self, collector: Any) -> list[Any]:  # noqa: ANN401, D102
        return collector.collect_unattached_volumes()

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="UnattachedEbsVolumeScanner",
            implementation_module="unio_collector.scanners.ec2.ebs.unattached_volume",
        )
