from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scanners.ec2.instance_inventory.collector import (
    collect_ec2_instance_inventory_context,
)
from unio_collector.scanners.inventory_evidence import InventoryEvidence

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


from unio_collector.scanners.ec2.inventory.collector import CachedEc2InventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class StoppedInstanceStorageCollector(CachedEc2InventoryCollector):
    """Collect provider evidence for ec2-stopped-instances-with-storage."""

    collection_name = "stopped_instances"

    def collect(self, context: ScannerContext) -> InventoryEvidence:  # noqa: D102
        inventory = collect_ec2_instance_inventory_context(context)
        return InventoryEvidence(
            records=inventory.collector.build_stopped_instance_records(
                instances_by_region=inventory.instances_by_region,
            ),
            regions=inventory.regions,
        )

    def collect_records(self, collector: Any) -> list[Any]:  # noqa: ANN401, D102
        return collector.collect_stopped_instances()

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="StoppedInstanceStorageScanner",
            implementation_module="unio_collector.scanners.ec2.instance_storage.stopped",
        )
