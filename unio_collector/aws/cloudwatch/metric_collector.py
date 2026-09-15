from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    AwsCollectionTaskResult,
    record_collection_results,
)
from unio_collector.aws.metric.collection import build_metric_observation, group_metric_requests_by_window
from unio_collector.aws.metric.read.reason import MetricReadReason
from unio_collector.aws.metric.read.values import MetricReadValues
from unio_collector.aws.metric.response_parser import MetricResponseParser
from unio_collector.aws.pagination import AwsPaginationHelper

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.metric.request import MetricRequest
    from unio_collector.aws.metric.summary import MetricSummary


class CloudWatchMetricCollector:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        region: str,
        audit_context: AwsAuditContext,
    ) -> None:
        self._session = session
        self._region = region
        self._audit_context = audit_context
        self.client = session.create_client(
            "cloudwatch",
            region_name=region,
            audit_context=audit_context,
        )
        self._pagination = AwsPaginationHelper()

    def collect_metric_summary(self, request: MetricRequest) -> MetricSummary:  # noqa: D102
        try:
            response = self.client.get_metric_statistics(
                Namespace=request.namespace,
                MetricName=request.metric_name,
                Dimensions=request.dimensions,
                StartTime=request.start_time,
                EndTime=request.end_time,
                Period=request.period,
                Statistics=[request.statistic],
            )
        except Exception as exc:  # noqa: BLE001
            return build_metric_observation(
                request,
                MetricReadValues([], status="unavailable", reason=MetricReadReason.READ_FAILED),
                limitation=f"CloudWatch metric read failed: {exc}",
            )
        return build_metric_observation(request, MetricResponseParser().parse_statistics(response, request.statistic))

    def collect_metric_summaries(  # noqa: D102
        self,
        requests: list[MetricRequest],
    ) -> list[MetricSummary]:
        if not requests:
            return []
        summaries: list[MetricSummary] = []
        for group in group_metric_requests_by_window(requests):
            summaries.extend(self._collect_metric_data_group(group))
        return summaries

    def _collect_metric_data_group(
        self,
        requests: list[MetricRequest],
    ) -> list[MetricSummary]:
        summaries_by_index: dict[int, MetricSummary] = {}
        chunk_results = self._collect_metric_data_chunks(requests)
        for result in chunk_results:
            query_ids = result.task.payload.get("query_ids")
            if not isinstance(query_ids, dict):
                continue
            if result.status != "completed" or result.value is None:
                for item in query_ids.values():
                    request_index, request = item
                    summaries_by_index[int(request_index)] = self.collect_metric_summary(
                        request,
                    )
                continue
            for query_id, (request_index, request) in query_ids.items():
                summaries_by_index[request_index] = build_metric_observation(
                    request,
                    result.value.get(query_id, MetricReadValues([], status="unavailable", reason=MetricReadReason.MISSING_RESULT)),
                )
        return [summaries_by_index[index] for index in sorted(summaries_by_index)]

    def _collect_metric_data_chunks(
        self,
        requests: list[MetricRequest],
    ) -> list[AwsCollectionTaskResult[dict[str, MetricReadValues]]]:
        tasks: list[AwsCollectionTask[dict[str, MetricReadValues]]] = []
        for chunk_start in range(0, len(requests), 500):
            chunk = requests[chunk_start : chunk_start + 500]
            query_ids = {f"m{chunk_start + index}": (chunk_start + index, request) for index, request in enumerate(chunk)}
            tasks.append(
                AwsCollectionTask(
                    name=(f"CloudWatchMetricCollector:cloudwatch:GetMetricData:{self._region}:{chunk_start}"),
                    scanner_id=self._audit_context.scanner_id,
                    collector_id="CloudWatchMetricCollector",
                    account_id=self._audit_context.recipient_account_id,
                    region=self._region,
                    service="cloudwatch",
                    operation="GetMetricData",
                    payload={"query_ids": query_ids},
                    collect=lambda query_ids=query_ids: self._fetch_metric_data(
                        query_ids,
                    ),
                ),
            )
        executor = AwsCollectionExecutor(
            max_workers=self._session.runtime_config.max_workers,
        )
        results = executor.run(tasks)
        record_collection_results(self._session, results)
        return results

    def _fetch_metric_data(
        self,
        query_ids: dict[str, tuple[int, MetricRequest]],
    ) -> dict[str, MetricReadValues]:
        first_request = next(iter(query_ids.values()))[1]
        request: dict[str, Any] = {
            "StartTime": first_request.start_time,
            "EndTime": first_request.end_time,
            "MetricDataQueries": [
                {
                    "Id": query_id,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": metric_request.namespace,
                            "MetricName": metric_request.metric_name,
                            "Dimensions": metric_request.dimensions,
                        },
                        "Period": metric_request.period,
                        "Stat": metric_request.statistic,
                    },
                    "ReturnData": True,
                }
                for query_id, (_index, metric_request) in query_ids.items()
            ],
        }
        pages = self._pagination.collect_token_pages(
            self.client,
            "get_metric_data",
            result_key="MetricDataResults",
            request_parameters=request,
        ).pages
        return MetricResponseParser().parse_pages(pages, list(query_ids))
