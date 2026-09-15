from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.cloudwatch import (
        CloudWatchLogMetricCollectionOptions,
        CloudWatchLogsCollector,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class CloudWatchEvidenceSource(Protocol):
    """CloudWatch Logs evidence methods required by scanners."""

    def collect_cached_log_groups_without_retention(
        self,
        definition: ScannerDefinition,
    ) -> list[Any]:
        """Return cached CloudWatch log groups without retention policies."""
        ...

    def collect_cached_log_group_activity(
        self,
        definition: ScannerDefinition,
        metric_options: CloudWatchLogMetricCollectionOptions | None = None,
    ) -> list[Any]:
        """Return cached CloudWatch log group activity evidence."""
        ...

    def create_cloudwatch_logs_collector(
        self,
        definition: ScannerDefinition,
    ) -> CloudWatchLogsCollector:
        """Create an audited CloudWatch Logs collector for scanner evidence reads."""
        ...
