from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.rds import RdsInventoryCollector

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


from unio_collector.scanners.regional.collection import RegionalInventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class RdsUtilizationReviewCollector(RegionalInventoryCollector):
    """Collect provider evidence for rds-utilization-review."""

    collector_id = "RdsInventoryCollector"

    collector_type = RdsInventoryCollector

    def collect_inventory_records(  # noqa: D102
        self,
        collector: RdsInventoryCollector,
        context: ScannerContext,
    ) -> list[object]:
        return list(
            collector.collect_instances(
                context.options.get_scan_period(),
            ),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="RdsUtilizationReviewScanner",
            implementation_module="unio_collector.scanners.rds.utilization_scanner",
        )
