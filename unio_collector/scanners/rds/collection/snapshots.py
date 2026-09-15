from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.rds import RdsInventoryCollector
from unio_collector.scanners.options import parse_scanner_option_int

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


from unio_collector.scanners.regional.collection import RegionalInventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class RdsSnapshotRetentionReviewCollector(RegionalInventoryCollector):
    """Collect provider evidence for rds-snapshot-retention-review."""

    collector_id = "RdsInventoryCollector"

    collector_type = RdsInventoryCollector

    def collect_inventory_records(  # noqa: D102
        self,
        collector: RdsInventoryCollector,
        context: ScannerContext,
    ) -> list[object]:
        del context
        return list(collector.collect_snapshots())

    def collect_inventory_metadata(  # noqa: D102
        self,
        collector: RdsInventoryCollector,
        context: ScannerContext,
    ) -> dict[str, object]:
        del collector
        older_than_days = parse_scanner_option_int(
            context.options.get("older_than_days", 90),
        )
        return {
            "older_than_days": max(1, older_than_days),
        }

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="RdsSnapshotRetentionReviewScanner",
            implementation_module="unio_collector.scanners.rds.snapshot_retention_scanner",
        )
