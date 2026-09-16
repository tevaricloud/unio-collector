from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.snapshot.inventory import SnapshotInventoryCollector

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


from unio_collector.scanners.regional.collection import RegionalInventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class SnapshotAgeReviewCollector(RegionalInventoryCollector):
    """Collect provider evidence for snapshot-age-review."""

    collector_id = "SnapshotInventoryCollector"

    collector_type = SnapshotInventoryCollector

    def collect_inventory_records(  # noqa: D102
        self,
        collector: SnapshotInventoryCollector,
        context: ScannerContext,
    ) -> list[object]:
        del context
        return list(collector.collect_snapshots())

    def collect_inventory_metadata(  # noqa: D102
        self,
        collector: SnapshotInventoryCollector,
        context: ScannerContext,
    ) -> dict[str, object]:
        del collector
        return {
            "older_than_days": context.options.get_int("older_than_days", 90),
        }

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="SnapshotAgeReviewScanner",
            implementation_module="unio_collector.scanners.snapshots",
        )
