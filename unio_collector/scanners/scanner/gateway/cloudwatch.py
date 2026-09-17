from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.cloudwatch import CloudWatchLogMetricCollectionOptions
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import (
        ScannerCloudWatchGatewayRuntime,
    )


@dataclass(frozen=True)
class ScannerCloudWatchGateway:  # noqa: D101
    runtime: ScannerCloudWatchGatewayRuntime
    definition: ScannerDefinition

    def collect_log_groups_without_retention(self) -> list[Any]:  # noqa: D102
        return self.runtime.collect_cached_log_groups_without_retention(self.definition)

    def collect_log_group_activity(  # noqa: D102
        self,
        metric_options: CloudWatchLogMetricCollectionOptions | None = None,
    ) -> list[Any]:
        return self.runtime.collect_cached_log_group_activity(
            self.definition,
            metric_options,
        )

    def create_logs_collector(self) -> Any:  # noqa: ANN401, D102
        return self.runtime.create_cloudwatch_logs_collector(self.definition)
