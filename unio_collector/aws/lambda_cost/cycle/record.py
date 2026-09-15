from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.lambda_cost.event_source import LambdaEventSourceRecord
    from unio_collector.aws.lambda_cost.function.tag_evidence import LambdaTagEvidence
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.aws.s3.lambda_notification import S3LambdaNotificationRecord


@dataclass(frozen=True)
class LambdaCostCycleRecord:  # noqa: D101
    function_name: str
    function_arn: str
    account_id: str
    region: str
    runtime: str | None
    memory_mb: int | None
    timeout_seconds: int | None
    architectures: list[str]
    reserved_concurrency: int | None
    provisioned_concurrency: int | None
    event_sources: list[LambdaEventSourceRecord]
    s3_notifications: list[S3LambdaNotificationRecord]
    destination_config: dict[str, object]
    environment_variables: dict[str, str]
    tags: dict[str, str]
    metric_summaries: list[MetricSummary]
    derived_metric_policy_fields_populated: bool = True
    tag_evidence: LambdaTagEvidence | None = None
    collection_errors: tuple[str, ...] = ()
