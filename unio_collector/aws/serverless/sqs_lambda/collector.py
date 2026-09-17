from __future__ import annotations  # noqa: D100

import threading
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.collection import RegionalAwsCollectionRunner
from unio_collector.aws.metric.request import MetricRequest
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.serverless.inventory_helpers import function_name_from_arn
from unio_collector.aws.serverless.sqs_lambda.collection_summary import (
    SqsLambdaCollectionSummary,
)
from unio_collector.aws.serverless.sqs_lambda.mapping import SqsLambdaMappingRecord

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.core.scan.period import ScanPeriod


class SqsLambdaInventoryCollector:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self._pagination = AwsPaginationHelper()
        self.collection_summary = SqsLambdaCollectionSummary()
        self._summary_lock = threading.Lock()
        self._region_summaries: list[tuple[int, int, int, int]] = []

    def collect_event_source_mappings(  # noqa: D102
        self,
        scan_period: ScanPeriod | None = None,
        *,
        max_mappings_per_region: int | None = None,
    ) -> list[SqsLambdaMappingRecord]:
        self._region_summaries = []
        regions = self.get_available_regions()
        result = RegionalAwsCollectionRunner(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="SqsLambdaInventoryCollector",
        ).collect_region_lists(
            regions=regions,
            service="lambda",
            operation="ListEventSourceMappings",
            collect_region=lambda region: self._collect_event_source_mappings_in_region(
                region,
                scan_period,
                max_mappings_per_region,
            ),
        )
        observed = sum(item[0] for item in self._region_summaries)
        retained = sum(item[1] for item in self._region_summaries)
        metric_count = sum(item[2] for item in self._region_summaries)
        metric_failures = sum(item[3] for item in self._region_summaries)
        regional_failures = len(result.get_failed_results())
        capped = observed > retained
        unavailable = bool(regions) and regional_failures == len(regions)
        partial = (bool(regional_failures) and not unavailable) or bool(metric_failures)
        limitations = list(result.build_warning_messages())
        if capped:
            limitations.append("Event source mapping evidence was bounded by the configured operational cap.")
        if metric_failures:
            limitations.append("One or more CloudWatch metric summaries were unavailable.")
        self.collection_summary = SqsLambdaCollectionSummary(
            mappings_observed=observed,
            retained_mappings=retained,
            mapping_cap_applied=capped,
            collection_complete=not capped and not regional_failures and not metric_failures,
            collection_capped=capped,
            collection_partial=partial,
            collection_unavailable=unavailable,
            metric_summary_count=metric_count,
            metric_failure_count=metric_failures,
            metric_retrieval_complete=metric_failures == 0,
            operational_mapping_cap=max_mappings_per_region,
            limitations=tuple(limitations),
        )
        return result.values

    def _collect_event_source_mappings_in_region(
        self,
        region: str,
        scan_period: ScanPeriod | None,
        max_mappings_per_region: int | None,
    ) -> list[SqsLambdaMappingRecord]:
        records: list[SqsLambdaMappingRecord] = []
        client = self.session.create_client(
            "lambda",
            region_name=region,
            audit_context=self.audit_context,
        )
        metric_collector = CloudWatchMetricCollector(
            self.session,
            region=region,
            audit_context=self.audit_context,
        )
        pages = self._pagination.collect_token_pages(
            client,
            "list_event_source_mappings",
            result_key="EventSourceMappings",
            request_parameters={"MaxItems": 100},
            request_cursor_key="Marker",
            response_cursor_keys=("NextMarker",),
        ).pages
        for response in pages:
            for mapping in response.get("EventSourceMappings", []):
                event_source_arn = mapping.get("EventSourceArn", "")
                if ":sqs:" not in event_source_arn:
                    continue
                function_name = function_name_from_arn(mapping.get("FunctionArn"))
                records.append(
                    SqsLambdaMappingRecord(
                        uuid=mapping.get("UUID", "unknown"),
                        function_arn=mapping.get("FunctionArn"),
                        function_name=function_name,
                        queue_arn=event_source_arn,
                        queue_name=event_source_arn.rsplit(":", 1)[-1],
                        state=mapping.get("State"),
                        batch_size=mapping.get("BatchSize"),
                        account_id=self.account_id,
                        region=region,
                        metric_summaries=[],
                        derived_metric_policy_fields_populated=False,
                    ),
                )
        records.sort(key=lambda record: (record.uuid, record.queue_arn, record.function_arn or ""))
        observed = len(records)
        retained_records = records if max_mappings_per_region is None else records[:max_mappings_per_region]
        enriched = self._add_metric_summaries(
            retained_records,
            metric_collector,
            scan_period,
        )
        metric_count = sum(len(record.metric_summaries) for record in enriched)
        metric_failures = sum(1 for record in enriched for metric in record.metric_summaries if metric.limitation)
        with self._summary_lock:
            self._region_summaries.append(
                (observed, len(enriched), metric_count, metric_failures),
            )
        return enriched

    def _add_metric_summaries(
        self,
        records: list[SqsLambdaMappingRecord],
        metric_collector: CloudWatchMetricCollector,
        scan_period: ScanPeriod | None,
    ) -> list[SqsLambdaMappingRecord]:
        if scan_period is None or not records:
            return records
        requests: list[MetricRequest] = []
        record_indexes: list[int] = []
        for index, record in enumerate(records):
            metric_requests = self._build_metric_requests(
                scan_period,
                record.function_name,
                record.queue_name,
            )
            requests.extend(metric_requests)
            record_indexes.extend([index] * len(metric_requests))
        summaries_by_record: dict[int, list[MetricSummary]] = {index: [] for index in range(len(records))}
        for index, summary in zip(
            record_indexes,
            metric_collector.collect_metric_summaries(requests),
            strict=True,
        ):
            summaries_by_record[index].append(summary)
        return [replace(record, metric_summaries=summaries_by_record[index]) for index, record in enumerate(records)]

    def _build_metric_requests(
        self,
        scan_period: ScanPeriod,
        function_name: str | None,
        queue_name: str,
    ) -> list[MetricRequest]:
        requests: list[MetricRequest] = []
        if function_name:
            lambda_dimensions = [{"Name": "FunctionName", "Value": function_name}]
            requests.extend(
                [
                    MetricRequest(
                        namespace="AWS/Lambda",
                        metric_name="Invocations",
                        dimensions=lambda_dimensions,
                        statistic="Sum",
                        period=86400,
                        start_time=scan_period.current_start_datetime,
                        end_time=scan_period.current_end_exclusive_datetime,
                    ),
                    MetricRequest(
                        namespace="AWS/Lambda",
                        metric_name="Errors",
                        dimensions=lambda_dimensions,
                        statistic="Sum",
                        period=86400,
                        start_time=scan_period.current_start_datetime,
                        end_time=scan_period.current_end_exclusive_datetime,
                    ),
                    MetricRequest(
                        namespace="AWS/Lambda",
                        metric_name="Duration",
                        dimensions=lambda_dimensions,
                        statistic="Average",
                        period=86400,
                        start_time=scan_period.current_start_datetime,
                        end_time=scan_period.current_end_exclusive_datetime,
                    ),
                ],
            )
        sqs_dimensions = [{"Name": "QueueName", "Value": queue_name}]
        requests.extend(
            [
                MetricRequest(
                    namespace="AWS/SQS",
                    metric_name="NumberOfMessagesReceived",
                    dimensions=sqs_dimensions,
                    statistic="Sum",
                    period=86400,
                    start_time=scan_period.current_start_datetime,
                    end_time=scan_period.current_end_exclusive_datetime,
                ),
                MetricRequest(
                    namespace="AWS/SQS",
                    metric_name="NumberOfEmptyReceives",
                    dimensions=sqs_dimensions,
                    statistic="Sum",
                    period=86400,
                    start_time=scan_period.current_start_datetime,
                    end_time=scan_period.current_end_exclusive_datetime,
                ),
                MetricRequest(
                    namespace="AWS/SQS",
                    metric_name="ApproximateAgeOfOldestMessage",
                    dimensions=sqs_dimensions,
                    statistic="Maximum",
                    period=86400,
                    start_time=scan_period.current_start_datetime,
                    end_time=scan_period.current_end_exclusive_datetime,
                ),
            ],
        )
        return requests

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self.selected_regions:
            return sorted(self.selected_regions)
        return sorted(self.session.get_available_regions("lambda"))
