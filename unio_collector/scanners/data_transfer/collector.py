from __future__ import annotations  # noqa: D100

from unio_collector.scanners.cost_explorer.daily.collector import CachedDailyCostCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class DataTransferCostReviewCollector(CachedDailyCostCollector):
    """Collect service evidence independently of private finding interpretation."""

    group_keys = ("SERVICE", "USAGE_TYPE")

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="DataTransferCostReviewScanner",
            implementation_module="unio_collector.scanners.data_transfer.cost_scanner",
        )
