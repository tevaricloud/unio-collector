from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cloudwatch import (
        CloudWatchLogMetricCollectionOptions,
        CloudWatchLogsCollector,
    )
    from unio_collector.scan_workflow.runner.evidence_gateway.protocols import (
        CloudWatchEvidenceSource,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class CloudWatchEvidenceGateway:
    """Delegate CloudWatch Logs evidence collection to the CloudWatch source."""

    def __init__(self, source: CloudWatchEvidenceSource) -> None:  # noqa: D107
        self._source = source

    def collect_cached_log_groups_without_retention(
        self,
        definition: ScannerDefinition,
    ) -> list[object]:
        """Return cached CloudWatch log groups without retention policies."""
        return self._source.collect_cached_log_groups_without_retention(definition)

    def collect_cached_log_group_activity(
        self,
        definition: ScannerDefinition,
        metric_options: CloudWatchLogMetricCollectionOptions | None = None,
    ) -> list[object]:
        """Return cached CloudWatch log group activity evidence."""
        return self._source.collect_cached_log_group_activity(
            definition,
            metric_options=metric_options,
        )

    def create_cloudwatch_logs_collector(
        self,
        definition: ScannerDefinition,
    ) -> CloudWatchLogsCollector:
        """Create an audited CloudWatch Logs collector for scanner evidence reads."""
        return self._source.create_cloudwatch_logs_collector(definition)
