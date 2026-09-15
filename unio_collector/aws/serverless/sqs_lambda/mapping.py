from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.metric.summary import MetricSummary


@dataclass(frozen=True)
class SqsLambdaMappingRecord:  # noqa: D101
    uuid: str
    function_arn: str | None
    function_name: str | None
    queue_arn: str
    queue_name: str
    state: str | None
    batch_size: int | None
    account_id: str
    region: str
    metric_summaries: list[MetricSummary]
    derived_metric_policy_fields_populated: bool = True
