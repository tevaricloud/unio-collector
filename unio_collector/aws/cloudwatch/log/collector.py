from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime, time
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch.log.constants import (
    CLOUDWATCH_LOG_METRIC_STATUS_COLLECTED,
    CLOUDWATCH_LOG_METRIC_STATUS_SKIPPED_BY_DETAIL_MODE,
)
from unio_collector.aws.cloudwatch.log.helpers import (
    get_log_group_metric_priority,
    millis_to_datetime,
)
from unio_collector.aws.cloudwatch.log.metric_options import (
    CloudWatchLogMetricCollectionOptions,
)
from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.inventory_helpers import RegionalInventoryCollectionHelper
from unio_collector.aws.log.group.activity import LogGroupActivityRecord
from unio_collector.aws.log.group.record import LogGroupRecord
from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.request import MetricRequest
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.regional.log_group_record import (
    RegionalLogGroupInventoryRecord,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.core.scan.period import ScanPeriod


class CloudWatchLogsCollector:
    """Read-only CloudWatch Logs collector."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
    ) -> None:
        self.session = session
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self._available_regions_cache: list[str] | None = None
        self._pagination = AwsPaginationHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.audit_context.recipient_account_id,
            audit_context=self.audit_context,
            collector_id="CloudWatchLogsCollector",
        )

    def collect_log_groups_without_retention(self) -> list[LogGroupRecord]:  # noqa: D102
        return self._collect_region_records(
            operation="DescribeLogGroups",
            collect_region=self._collect_log_groups_without_retention_in_region,
        )

    def collect_log_group_activity(  # noqa: D102
        self,
        scan_period: ScanPeriod,
        metric_options: CloudWatchLogMetricCollectionOptions | None = None,
    ) -> list[LogGroupActivityRecord]:
        metric_options = metric_options or CloudWatchLogMetricCollectionOptions()
        if metric_options.should_prioritize_globally():
            return self._collect_log_group_activity_with_global_metric_priority(
                scan_period,
                metric_options,
            )
        return self._collect_region_records(
            operation="DescribeLogGroups",
            collect_region=lambda region: self._collect_log_group_activity_in_region(
                region,
                scan_period,
                metric_options,
            ),
        )

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._available_regions_cache is not None:
            return self._available_regions_cache
        if self.selected_regions:
            self._available_regions_cache = sorted(self.selected_regions)
            return self._available_regions_cache
        self._available_regions_cache = sorted(
            self.session.get_available_regions("logs"),
        )
        return self._available_regions_cache

    def _collect_region_records(
        self,
        *,
        operation: str,
        collect_region: Callable[[str], list[Any]],
    ) -> list[Any]:
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="logs",
            operation=operation,
            collect_region=collect_region,
        )

    def _collect_log_group_activity_with_global_metric_priority(
        self,
        scan_period: ScanPeriod,
        metric_options: CloudWatchLogMetricCollectionOptions,
    ) -> list[LogGroupActivityRecord]:
        inventory_records = self._collect_region_records(
            operation="DescribeLogGroups",
            collect_region=self._collect_log_group_inventory_in_region,
        )
        selected_keys = self._select_global_metric_log_group_keys(
            inventory_records,
            metric_options,
        )
        metrics_by_key: dict[tuple[str, str], list[MetricSummary]] = {}
        for region in sorted({record.region for record in inventory_records}):
            selected_names = sorted(
                record.log_group_name for record in inventory_records if record.region == region and (record.region, record.log_group_name) in selected_keys
            )
            if not selected_names:
                continue
            metrics = CloudWatchMetricCollector(
                self.session,
                region=region,
                audit_context=self.audit_context,
            )
            for name, metric_summaries in self._collect_log_metrics_for_groups(
                metrics,
                selected_names,
                scan_period,
            ).items():
                metrics_by_key[(region, name)] = metric_summaries
        return [
            self._build_activity_record(
                inventory_record,
                metrics=metrics_by_key.get(
                    (inventory_record.region, inventory_record.log_group_name),
                    [],
                ),
                metrics_collected=(
                    inventory_record.region,
                    inventory_record.log_group_name,
                )
                in selected_keys,
            )
            for inventory_record in inventory_records
        ]

    def _collect_log_groups_without_retention_in_region(
        self,
        region: str,
    ) -> list[LogGroupRecord]:
        records: list[LogGroupRecord] = []
        client = self.session.create_client(
            "logs",
            region_name=region,
            audit_context=self.audit_context,
        )
        pages = self._pagination.collect_token_pages(
            client,
            "describe_log_groups",
            result_key="logGroups",
            request_parameters={"limit": 50},
            request_cursor_key="nextToken",
            response_cursor_keys=("nextToken",),
        ).pages
        for page in pages:
            for group in page.get("logGroups", []):
                if "retentionInDays" in group:
                    continue
                records.append(
                    LogGroupRecord(
                        log_group_name=group["logGroupName"],
                        region=region,
                        stored_bytes=group.get("storedBytes"),
                    ),
                )
        return records

    def _collect_log_group_activity_in_region(
        self,
        region: str,
        scan_period: ScanPeriod,
        metric_options: CloudWatchLogMetricCollectionOptions,
    ) -> list[LogGroupActivityRecord]:
        client = self.session.create_client(
            "logs",
            region_name=region,
            audit_context=self.audit_context,
        )
        metrics = CloudWatchMetricCollector(
            self.session,
            region=region,
            audit_context=self.audit_context,
        )
        regional_groups = [
            record.log_group
            for record in self._collect_log_group_inventory_from_client(
                client,
                region,
            )
        ]
        metric_log_group_names = self._select_metric_log_group_names(
            regional_groups,
            metric_options,
        )
        metrics_by_name = self._collect_log_metrics_for_groups(
            metrics,
            metric_log_group_names,
            scan_period,
        )
        selected_names = set(metric_log_group_names)
        records: list[LogGroupActivityRecord] = []
        for group in regional_groups:
            name = str(group["logGroupName"])
            records.append(
                self._build_activity_record(
                    RegionalLogGroupInventoryRecord(
                        region=region,
                        log_group=group,
                    ),
                    metrics=metrics_by_name.get(name, []),
                    metrics_collected=name in selected_names,
                ),
            )
        return records

    def _collect_log_group_inventory_in_region(
        self,
        region: str,
    ) -> list[RegionalLogGroupInventoryRecord]:
        client = self.session.create_client(
            "logs",
            region_name=region,
            audit_context=self.audit_context,
        )
        return self._collect_log_group_inventory_from_client(client, region)

    def _collect_log_group_inventory_from_client(
        self,
        client: Any,  # noqa: ANN401
        region: str,
    ) -> list[RegionalLogGroupInventoryRecord]:
        records: list[RegionalLogGroupInventoryRecord] = []
        pages = self._pagination.collect_token_pages(
            client,
            "describe_log_groups",
            result_key="logGroups",
            request_parameters={"limit": 50},
            request_cursor_key="nextToken",
            response_cursor_keys=("nextToken",),
        ).pages
        for page in pages:
            for group in page.get("logGroups", []):
                if "logGroupName" not in group:
                    continue
                records.append(
                    RegionalLogGroupInventoryRecord(
                        region=region,
                        log_group=group,
                    ),
                )
        return records

    def _select_global_metric_log_group_keys(
        self,
        records: list[RegionalLogGroupInventoryRecord],
        metric_options: CloudWatchLogMetricCollectionOptions,
    ) -> set[tuple[str, str]]:
        if len(records) <= metric_options.max_metric_log_groups:
            return {(record.region, record.log_group_name) for record in records}
        prioritized_records = sorted(
            records,
            key=lambda record: get_log_group_metric_priority(record.log_group),
        )
        return {(record.region, record.log_group_name) for record in prioritized_records[: metric_options.max_metric_log_groups]}

    def _build_activity_record(
        self,
        inventory_record: RegionalLogGroupInventoryRecord,
        *,
        metrics: list[MetricSummary],
        metrics_collected: bool,
    ) -> LogGroupActivityRecord:
        group = inventory_record.log_group
        return LogGroupActivityRecord(
            log_group_name=inventory_record.log_group_name,
            region=inventory_record.region,
            stored_bytes=group.get("storedBytes"),
            retention_in_days=group.get("retentionInDays"),
            creation_time=millis_to_datetime(group.get("creationTime")),
            tags={},
            metrics=metrics,
            metric_collection_status=(CLOUDWATCH_LOG_METRIC_STATUS_COLLECTED if metrics_collected else CLOUDWATCH_LOG_METRIC_STATUS_SKIPPED_BY_DETAIL_MODE),
            metric_collection_reason=(
                None
                if metrics_collected
                else ("CloudWatch log ingestion metrics were skipped by metric_detail_mode=prioritized after selecting higher-signal log groups.")
            ),
        )

    def _select_metric_log_group_names(
        self,
        regional_groups: list[dict[str, Any]],
        metric_options: CloudWatchLogMetricCollectionOptions,
    ) -> list[str]:
        if not metric_options.should_prioritize(len(regional_groups)):
            return [str(group["logGroupName"]) for group in regional_groups if "logGroupName" in group]
        prioritized_groups = sorted(
            regional_groups,
            key=get_log_group_metric_priority,
        )
        return [str(group["logGroupName"]) for group in prioritized_groups[: metric_options.max_metric_log_groups_per_region] if "logGroupName" in group]

    def _collect_log_metrics_for_groups(
        self,
        collector: CloudWatchMetricCollector,
        log_group_names: list[str],
        scan_period: ScanPeriod,
    ) -> dict[str, list[MetricSummary]]:
        requests: list[MetricRequest] = []
        owners: list[str] = []
        for log_group_name in log_group_names:
            group_requests = self._build_log_metric_requests(
                log_group_name,
                scan_period,
            )
            requests.extend(group_requests)
            owners.extend([log_group_name] * len(group_requests))
        summaries = collector.collect_metric_summaries(requests)
        metrics_by_name: dict[str, list[MetricSummary]] = {log_group_name: [] for log_group_name in log_group_names}
        for log_group_name, summary in zip(owners, summaries, strict=True):
            metrics_by_name.setdefault(log_group_name, []).append(summary)
        return metrics_by_name

    def _build_log_metric_requests(
        self,
        log_group_name: str,
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
        dimensions = [{"Name": "LogGroupName", "Value": log_group_name}]
        return [
            MetricRequest(
                namespace="AWS/Logs",
                metric_name=metric_name,
                dimensions=dimensions,
                statistic="Sum",
                period=3600,
                start_time=start_time,
                end_time=end_time,
                collection_context=MetricCollectionContext.LOG_GROUP,
            )
            for metric_name in ("IncomingBytes", "IncomingLogEvents")
        ]
