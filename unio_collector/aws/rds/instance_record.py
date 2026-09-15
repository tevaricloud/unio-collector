from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.metric.summary import MetricSummary


@dataclass(frozen=True)
class RdsInstanceRecord:  # noqa: D101
    db_instance_identifier: str
    db_instance_class: str
    engine: str
    status: str
    account_id: str
    region: str
    arn: str | None
    allocated_storage_gib: int | None
    tags: dict[str, str]
    metrics: list[MetricSummary]
