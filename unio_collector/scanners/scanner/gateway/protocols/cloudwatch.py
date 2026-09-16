from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.cloudwatch import (
        CloudWatchLogMetricCollectionOptions,
        CloudWatchLogsCollector,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerCloudWatchGatewayRuntime(Protocol):
    """Runtime capabilities required by scanner CloudWatch gateways."""

    def collect_cached_log_groups_without_retention(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[Any]: ...

    def collect_cached_log_group_activity(  # noqa: D102
        self,
        definition: ScannerDefinition,
        metric_options: CloudWatchLogMetricCollectionOptions | None = None,
    ) -> list[Any]: ...

    def create_cloudwatch_logs_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> CloudWatchLogsCollector: ...
