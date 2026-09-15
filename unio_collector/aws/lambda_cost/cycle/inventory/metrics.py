# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.aws.metric.request import MetricRequest

if TYPE_CHECKING:
    from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
    from unio_collector.aws.lambda_cost.cycle.record import LambdaCostCycleRecord
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.core.scan.period import ScanPeriod


class LambdaMetricCollectionMixin:  # noqa: D101
    def _build_lambda_metric_requests(
        self,
        scan_period: ScanPeriod,
        function_name: str,
    ) -> list[MetricRequest]:
        dimensions = [{"Name": "FunctionName", "Value": function_name}]
        return [
            MetricRequest(
                namespace="AWS/Lambda",
                metric_name="Invocations",
                dimensions=dimensions,
                statistic="Sum",
                period=86400,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
            ),
            MetricRequest(
                namespace="AWS/Lambda",
                metric_name="Duration",
                dimensions=dimensions,
                statistic="Average",
                period=86400,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
            ),
            MetricRequest(
                namespace="AWS/Lambda",
                metric_name="Errors",
                dimensions=dimensions,
                statistic="Sum",
                period=86400,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
            ),
            MetricRequest(
                namespace="AWS/Lambda",
                metric_name="Throttles",
                dimensions=dimensions,
                statistic="Sum",
                period=86400,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
            ),
        ]

    def _build_log_metric_requests(
        self,
        scan_period: ScanPeriod,
        function_name: str,
    ) -> list[MetricRequest]:
        dimensions = [{"Name": "LogGroupName", "Value": f"/aws/lambda/{function_name}"}]
        return [
            MetricRequest(
                namespace="AWS/Logs",
                metric_name="IncomingBytes",
                dimensions=dimensions,
                statistic="Sum",
                period=86400,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
            ),
        ]

    def _collect_metrics_for_records(
        self,
        collector: CloudWatchMetricCollector,
        scan_period: ScanPeriod,
        records: list[LambdaCostCycleRecord],
    ) -> dict[str, list[MetricSummary]]:
        requests: list[MetricRequest] = []
        owners: list[str] = []
        for record in records:
            function_requests = [
                *self._build_lambda_metric_requests(scan_period, record.function_name),
                *self._build_log_metric_requests(scan_period, record.function_name),
            ]
            requests.extend(function_requests)
            owners.extend([record.function_name] * len(function_requests))
        summaries = collector.collect_metric_summaries(requests)
        by_function: dict[str, list[MetricSummary]] = {record.function_name: [] for record in records}
        for function_name, summary in zip(owners, summaries, strict=True):
            by_function.setdefault(function_name, []).append(summary)
        return by_function

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self.selected_regions:
            return sorted(self.selected_regions)
        return sorted(self.session.get_available_regions("lambda"))
