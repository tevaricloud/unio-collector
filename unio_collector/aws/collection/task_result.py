from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.collection.task import AwsCollectionTask, AwsCollectionTaskStatus


@dataclass(frozen=True)
class AwsCollectionTaskResult[T]:  # noqa: D101
    task: AwsCollectionTask[T]
    status: AwsCollectionTaskStatus
    duration_ms: int
    value: T | None = None
    result_count: int = 0
    resource_count: int = 0
    metric_datapoint_count: int = 0
    page_count: int = 0
    error_code: str | None = None
    error_message: str | None = None

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "name": self.task.name,
            "scanner_id": self.task.scanner_id,
            "collector_id": self.task.collector_id,
            "account_id": self.task.account_id,
            "region": self.task.region,
            "service": self.task.service,
            "operation": self.task.operation,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "result_count": self.result_count,
            "resource_count": self.resource_count,
            "metric_datapoint_count": self.metric_datapoint_count,
            "page_count": self.page_count,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }
