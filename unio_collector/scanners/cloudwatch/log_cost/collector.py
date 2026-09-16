from __future__ import annotations  # noqa: D100

from unio_collector.scanners.cloudwatch.log_activity.collector import CloudWatchLogActivityCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class CloudWatchLogCostRelevanceCollector(CloudWatchLogActivityCollector):
    """Collect provider evidence for cloudwatch-log-cost-and-relevance-review."""

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CloudWatchLogCostRelevanceScanner",
            implementation_module="unio_collector.scanners.cloudwatch.log_cost.scanner",
        )
