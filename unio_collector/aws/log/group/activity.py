from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.aws.cloudwatch.log.constants import (
    CLOUDWATCH_LOG_METRIC_STATUS_COLLECTED,
)

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.aws.metric.summary import MetricSummary


@dataclass(frozen=True)
class LogGroupActivityRecord:  # noqa: D101
    log_group_name: str
    region: str
    stored_bytes: int | None
    retention_in_days: int | None
    creation_time: datetime | None
    tags: dict[str, str]
    metrics: list[MetricSummary]
    metric_collection_status: str = CLOUDWATCH_LOG_METRIC_STATUS_COLLECTED
    metric_collection_reason: str | None = None
