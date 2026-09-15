# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from datetime import UTC, datetime, time
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.collection import (
    AwsCollectionTask,
    AwsCollectionTaskResult,
)
from unio_collector.aws.dynamodb.tag_result import DynamoDbTableTagResult
from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.request import MetricRequest
from unio_collector.aws.response_admission import ProviderResponseError, iter_response_rows, require_response_rows

if TYPE_CHECKING:
    from unio_collector.aws.dynamodb.table import DynamoDbTableDetail
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.core.scan.period import ScanPeriod

DYNAMODB_RETENTION_DETAIL_MODES = {"full", "summary"}
DYNAMODB_METRIC_DETAIL_MODES = {"full", "summary"}
DYNAMODB_AUTOSCALING_DETAIL_MODES = {"full", "summary"}
DYNAMODB_TABLE_DETAIL_REGIONAL_MODES = {"full", "billing-active"}
TABLE_DETAIL_SKIPPED_ERROR = "table_detail:skipped_by_regional_collection_mode"
RETENTION_DETAIL_SKIPPED_ERRORS = (
    "describe_continuous_backups:skipped_by_retention_detail_mode",
    "describe_time_to_live:skipped_by_retention_detail_mode",
)
METRIC_DETAIL_SKIPPED_ERROR = "cloudwatch_metrics:skipped_by_metric_detail_mode"
AUTOSCALING_DETAIL_SKIPPED_ERROR = "application_autoscaling:skipped_by_autoscaling_detail_mode"


class DynamoDbMetricMixin:  # noqa: D101
    def _build_dynamodb_tag_tasks(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        table_details: list[DynamoDbTableDetail],
    ) -> list[AwsCollectionTask[DynamoDbTableTagResult]]:
        tasks: list[AwsCollectionTask[DynamoDbTableTagResult]] = []
        for detail in table_details:
            if detail.table is None:
                continue
            table_arn = str(detail.table.get("TableArn") or "")
            if not table_arn:
                continue
            tasks.append(
                AwsCollectionTask(
                    name=f"DynamoDbInventoryCollector:tags:{detail.table_name}",
                    scanner_id=self.audit_context.scanner_id,
                    collector_id=self.audit_context.collector,
                    account_id=self.account_id,
                    region=region,
                    service="dynamodb",
                    operation="ListTagsOfResource",
                    payload={
                        "table_name": detail.table_name,
                        "table_arn": table_arn,
                    },
                    collect=lambda detail=detail, table_arn=table_arn: self._collect_table_tag_result(
                        client,
                        detail.table_name,
                        table_arn,
                    ),
                ),
            )
        return tasks

    def _collect_table_tag_result(
        self,
        client: Any,  # noqa: ANN401
        table_name: str,
        table_arn: str,
    ) -> DynamoDbTableTagResult:
        permission_errors: list[str] = []
        tags = self._get_table_tags(client, table_arn, permission_errors)
        return DynamoDbTableTagResult(
            table_name=table_name,
            tags=tags,
            permission_errors=permission_errors,
        )

    def _build_table_tags_from_results(
        self,
        table_details: list[DynamoDbTableDetail],
        results: list[AwsCollectionTaskResult[DynamoDbTableTagResult]],
        permission_errors: list[str],
    ) -> dict[str, dict[str, str]]:
        tags_by_table: dict[str, dict[str, str]] = {}
        expected_names = {detail.table_name for detail in table_details}
        for result in results:
            table_name = str(result.task.payload.get("table_name") or "")
            if not table_name or table_name not in expected_names:
                continue
            if result.status == "completed" and result.value is not None:
                if not result.value.permission_errors:
                    tags_by_table[table_name] = dict(result.value.tags)
                self._extend_unique(permission_errors, result.value.permission_errors)
                continue
            if result.error_code:
                self._extend_unique(
                    permission_errors,
                    [f"list_tags_of_resource:{result.error_code}"],
                )
        return tags_by_table

    def _convert_tag_list(self, tags: object) -> dict[str, str]:
        result: dict[str, str] = {}
        for tag in require_response_rows({"Tags": tags}, "Tags"):
            key, value = tag.get("Key"), tag.get("Value")
            if not isinstance(key, str) or not isinstance(value, str) or key in result:
                raise ProviderResponseError
            result[key] = value
        return result

    def _build_autoscaling_client_for_provisioned_tables(
        self,
        region: str,
        tables: list[dict[str, Any]],
        permission_errors: list[str],
    ) -> Any | None:  # noqa: ANN401
        if not self._has_provisioned_capacity(tables):
            return None
        if self.autoscaling_detail_mode == "summary":
            permission_errors.append(AUTOSCALING_DETAIL_SKIPPED_ERROR)
            return None
        return self._safe_client(
            "application-autoscaling",
            region,
            permission_errors,
        )

    def _has_provisioned_capacity(self, tables: list[dict[str, Any]]) -> bool:
        return self._table_classifier.has_provisioned_capacity(tables)

    def _collect_metric_rollup(
        self,
        region: str,
        table_names: list[str],
        scan_period: ScanPeriod | None,
        permission_errors: list[str],
    ) -> dict[str, Any]:
        empty = self._build_empty_metric_rollup()
        if self.metric_detail_mode == "summary":
            permission_errors.append(METRIC_DETAIL_SKIPPED_ERROR)
            return empty
        if not table_names or scan_period is None:
            return empty
        try:
            collector = CloudWatchMetricCollector(
                self.session,
                region=region,
                audit_context=self.audit_context,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="cloudwatch:CreateClient",
                exc=exc,
            )
            return empty
        requests: list[MetricRequest] = []
        owners: list[str] = []
        for table_name in table_names:
            table_requests = self._build_table_metric_requests(
                table_name,
                scan_period,
            )
            requests.extend(table_requests)
            owners.extend([table_name] * len(table_requests))
        summaries = collector.collect_metric_summaries(requests)
        metrics_by_table: dict[str, list[MetricSummary]] = {table_name: [] for table_name in table_names}
        for table_name, summary in zip(owners, summaries, strict=True):
            metrics_by_table.setdefault(table_name, []).append(summary)
        return self._summarize_table_metrics(metrics_by_table)

    def _build_empty_metric_rollup(self) -> dict[str, Any]:
        return {
            "metric_table_count": 0,
            "metric_observation_count": 0,
            "consumed_capacity_table_count": 0,
            "throttle_signal_table_count": 0,
            "system_error_signal_table_count": 0,
            "average_daily_read_capacity_units": None,
            "average_daily_write_capacity_units": None,
            "sample_metric_table_names": [],
            "observed_metric_names": [],
        }

    def _build_table_metric_requests(
        self,
        table_name: str,
        scan_period: ScanPeriod,
    ) -> list[MetricRequest]:
        start_time = datetime.combine(
            scan_period.current_start_date,
            time.min,
            tzinfo=UTC,
        )
        end_time = datetime.combine(
            scan_period.current_end_exclusive,
            time.min,
            tzinfo=UTC,
        )
        dimensions = [{"Name": "TableName", "Value": table_name}]
        metric_specs = (
            ("ConsumedReadCapacityUnits", "Sum"),
            ("ConsumedWriteCapacityUnits", "Sum"),
            ("ReadThrottleEvents", "Sum"),
            ("WriteThrottleEvents", "Sum"),
            ("ThrottledRequests", "Sum"),
            ("SystemErrors", "Sum"),
            ("SuccessfulRequestLatency", "Average"),
        )
        return [
            MetricRequest(
                namespace="AWS/DynamoDB",
                metric_name=metric_name,
                dimensions=dimensions,
                statistic=statistic,
                period=86400,
                start_time=start_time,
                end_time=end_time,
                collection_context=MetricCollectionContext.DYNAMODB_TABLE,
            )
            for metric_name, statistic in metric_specs
        ]

    def _summarize_table_metrics(
        self,
        metrics_by_table: dict[str, list[MetricSummary]],
    ) -> dict[str, Any]:
        metric_table_names: list[str] = []
        consumed_capacity_table_names: list[str] = []
        throttle_table_names: list[str] = []
        system_error_table_names: list[str] = []
        observed_metric_names: set[str] = set()
        read_values: list[Decimal] = []
        write_values: list[Decimal] = []
        metric_observation_count = 0
        for table_name, summaries in metrics_by_table.items():
            observed = [summary for summary in summaries if summary.observed_average is not None]
            if not observed:
                continue
            metric_table_names.append(table_name)
            metric_observation_count += len(observed)
            observed_metric_names.update(summary.metric_name for summary in observed)
            read_values.extend(
                summary.observed_average
                for summary in observed
                if (summary.metric_name == "ConsumedReadCapacityUnits" and summary.observed_average is not None)
            )
            write_values.extend(
                summary.observed_average
                for summary in observed
                if (summary.metric_name == "ConsumedWriteCapacityUnits" and summary.observed_average is not None)
            )
            if self._has_metric_value(
                observed,
                "ConsumedReadCapacityUnits",
                "ConsumedWriteCapacityUnits",
            ):
                consumed_capacity_table_names.append(table_name)
            if self._has_metric_value(
                observed,
                "ReadThrottleEvents",
                "WriteThrottleEvents",
                "ThrottledRequests",
            ):
                throttle_table_names.append(table_name)
            if self._has_metric_value(observed, "SystemErrors"):
                system_error_table_names.append(table_name)
        return {
            "metric_table_count": len(metric_table_names),
            "metric_observation_count": metric_observation_count,
            "consumed_capacity_table_count": len(consumed_capacity_table_names),
            "throttle_signal_table_count": len(throttle_table_names),
            "system_error_signal_table_count": len(system_error_table_names),
            "average_daily_read_capacity_units": self._average_decimal(read_values),
            "average_daily_write_capacity_units": self._average_decimal(write_values),
            "sample_metric_table_names": self._limit_samples(metric_table_names),
            "observed_metric_names": self._limit_samples(sorted(observed_metric_names)),
        }

    def _has_metric_value(
        self,
        summaries: list[MetricSummary],
        *metric_names: str,
    ) -> bool:
        return any(summary.metric_name in metric_names and summary.observed_average is not None and summary.observed_average > 0 for summary in summaries)

    def _average_decimal(self, values: list[Decimal]) -> Decimal | None:
        if not values:
            return None
        return (sum(values, Decimal(0)) / Decimal(len(values))).quantize(
            Decimal("0.01"),
        )

    def _collect_table_pitr_enabled(
        self,
        client: Any,  # noqa: ANN401
        table_name: str,
        permission_errors: list[str],
    ) -> bool:
        try:
            response = client.describe_continuous_backups(TableName=table_name)
            return self._table_classifier.is_pitr_enabled(response)
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="describe_continuous_backups",
                exc=exc,
            )
            return False

    def _collect_table_ttl_enabled(
        self,
        client: Any,  # noqa: ANN401
        table_name: str,
        permission_errors: list[str],
    ) -> bool:
        try:
            response = client.describe_time_to_live(TableName=table_name)
            return self._table_classifier.is_ttl_enabled(response)
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="describe_time_to_live",
                exc=exc,
            )
            return False

    def _get_table_tags(
        self,
        client: Any,  # noqa: ANN401
        table_arn: str,
        permission_errors: list[str],
    ) -> dict[str, str]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_tags_of_resource",
                result_key="Tags",
                request_parameters={"ResourceArn": table_arn},
                request_cursor_key="NextToken",
                response_cursor_keys=("NextToken", "nextToken"),
            )
            return self._convert_tag_list(list(iter_response_rows(result.pages, "Tags")))
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="list_tags_of_resource",
                exc=exc,
            )
            return {}

    def _collect_scalable_targets(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        return self._collect_application_autoscaling_items(
            client,
            "describe_scalable_targets",
            "ScalableTargets",
            permission_errors,
        )

    def _collect_scaling_policies(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        return self._collect_application_autoscaling_items(
            client,
            "describe_scaling_policies",
            "ScalingPolicies",
            permission_errors,
        )
