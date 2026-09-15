from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.cloudwatch.log_retention.evidence import (
    CloudWatchLogRetentionEvidence,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class CloudWatchLogRetentionCollector(BaseUnioScanner):
    """Collect provider evidence for cloudwatch-log-groups-without-retention."""

    def collect(self, context: ScannerContext) -> CloudWatchLogRetentionEvidence:  # noqa: D102
        return CloudWatchLogRetentionEvidence(
            records=context.cloudwatch.collect_log_groups_without_retention(),
            regions=self.get_regions_scanned(context),
        )

    def get_regions_scanned(self, context: ScannerContext) -> list[str]:  # noqa: D102
        collector = context.cloudwatch.create_logs_collector()
        return collector.get_available_regions()

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CloudWatchLogRetentionScanner",
            implementation_module="unio_collector.scanners.cloudwatch.log_retention.scanner",
        )
