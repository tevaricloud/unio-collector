from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.extended_support import (
    ExtendedSupportInventoryCollector,
)

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


from unio_collector.scanners.regional.collection import RegionalInventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class ExtendedSupportAndEolReviewCollector(RegionalInventoryCollector):
    """Collect provider evidence for extended-support-and-eol-review."""

    collector_id = "ExtendedSupportInventoryCollector"

    collector_type = ExtendedSupportInventoryCollector

    def collect_inventory_records(  # noqa: D102
        self,
        collector: ExtendedSupportInventoryCollector,
        context: ScannerContext,
    ) -> list[object]:
        lambda_inventory = context.lambda_.collect_function_inventory()
        return list(
            collector.collect_resources(
                lambda_function_inventory_by_region=lambda_inventory,
            ),
        )

    def collect_inventory_regions(  # noqa: D102
        self,
        collector: ExtendedSupportInventoryCollector,
        context: ScannerContext,
    ) -> list[str]:
        del context
        return sorted(
            set(collector.get_available_regions("rds"))
            | set(collector.get_available_regions("lambda"))
            | set(collector.get_available_regions("ec2"))
            | set(collector.get_available_regions("elasticache"))
            | set(collector.get_available_regions("opensearch"))
            | set(collector.get_available_regions("eks")),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="ExtendedSupportAndEolReviewScanner",
            implementation_module="unio_collector.scanners.lifecycle.eol_scanner",
        )
