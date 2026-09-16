from __future__ import annotations  # noqa: D100

from unio_collector.scanners.cloudwatch.log_activity.collector import CloudWatchLogActivityCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class CloudWatchIdleLogReviewCollector(CloudWatchLogActivityCollector):
    """Collect provider evidence for cloudwatch-idle-log-review."""

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CloudWatchIdleLogReviewScanner",
            implementation_module="unio_collector.scanners.cloudwatch.idle_log",
        )
