# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    record_collection_results,
)
from unio_collector.aws.lambda_cost.cycle.collection_summary import (
    LambdaCostCycleCollectionSummary,
)
from unio_collector.aws.lambda_cost.event_source import LambdaEventSourceRecord
from unio_collector.aws.s3.lambda_notification import S3LambdaNotificationRecord
from unio_collector.aws.serverless.inventory_helpers import (
    event_source_type,
    extract_s3_filter_rules,
    function_name_from_arn,
    normalized_s3_bucket_region,
    optional_str,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audit import AuditedAwsClient
    from unio_collector.aws.s3 import S3BucketIndexResult


class LambdaS3SignalCollectionMixin:  # noqa: D101
    def _collect_all_event_source_mappings(
        self,
        client: AuditedAwsClient,
    ) -> dict[str, list[LambdaEventSourceRecord]]:
        records_by_function: dict[str, list[LambdaEventSourceRecord]] = {}
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
                function_name = function_name_from_arn(
                    optional_str(mapping.get("FunctionArn")),
                )
                if not function_name:
                    continue
                records_by_function.setdefault(function_name, []).append(
                    LambdaEventSourceRecord(
                        source_type=event_source_type(mapping.get("EventSourceArn")),
                        source_arn=mapping.get("EventSourceArn"),
                        uuid=mapping.get("UUID"),
                        state=mapping.get("State"),
                        batch_size=mapping.get("BatchSize"),
                    ),
                )
        return records_by_function

    def _collect_s3_notifications(
        self,
        *,
        s3_bucket_index: S3BucketIndexResult | None = None,
    ) -> list[S3LambdaNotificationRecord]:
        records: list[S3LambdaNotificationRecord] = []
        if self.s3_notification_detail_mode == "summary":
            self.s3_notification_scan_summary = self._s3_notification_bucket_selector.build_summary_skipped_by_detail_mode()
            self.collection_summary = LambdaCostCycleCollectionSummary(
                s3_notification_detail_mode=self.s3_notification_detail_mode,
                detail_intentionally_skipped=True,
                operational_bucket_cap=self.max_s3_buckets,
                limitations=("S3 notification detail was intentionally skipped by configuration.",),
            )
            return records
        bucket_index_source = "shared_s3_bucket_index"
        if s3_bucket_index is None:
            bucket_index_source = "direct_list_buckets"
            client = self.session.create_client(
                "s3",
                region_name=None,
                audit_context=self.audit_context,
            )
            try:
                raw_buckets = client.list_buckets().get("Buckets", [])
            except Exception:  # noqa: BLE001
                self.s3_notification_scan_summary = replace(
                    self.s3_notification_scan_summary,
                    bucket_index_source=bucket_index_source,
                    selection_mode="bucket_inventory_unavailable",
                    policy_scan_skipped_reason="compatibility_option_not_applied",
                )
                self.collection_summary = LambdaCostCycleCollectionSummary(
                    s3_notification_detail_mode=self.s3_notification_detail_mode,
                    collection_unavailable=True,
                    operational_bucket_cap=self.max_s3_buckets,
                    limitations=("S3 bucket population could not be collected.",),
                )
                return records
            buckets = [bucket for bucket in raw_buckets if isinstance(bucket, dict)]
            bucket_index_limitations: tuple[str, ...] = ()
        else:
            buckets = [self._s3_notification_bucket_selector.build_bucket_candidate(bucket) for bucket in s3_bucket_index.buckets]
            bucket_index_limitations = tuple(s3_bucket_index.warnings)
        selection_mode = "shared_bucket_index_cap" if bucket_index_source == "shared_s3_bucket_index" else "direct_bucket_cap"
        selection = self._s3_notification_bucket_selector.select_buckets(
            buckets,
            summary=self.s3_notification_scan_summary,
        )
        buckets_to_check = selection.buckets
        self.s3_notification_scan_summary = selection.summary
        workers = max(
            1,
            min(self.s3_notification_worker_count, max(1, len(buckets_to_check))),
        )
        task_results = AwsCollectionExecutor(max_workers=workers).run(
            self._build_s3_notification_tasks(buckets_to_check),
        )
        record_collection_results(self.session, task_results)
        error_count = sum(1 for result in task_results if result.status != "completed")
        success_count = len(task_results) - error_count
        for result in task_results:
            if result.status == "completed" and result.value:
                records.extend(result.value)
        self.s3_notification_scan_summary = replace(
            self.s3_notification_scan_summary,
            notification_read_error_count=error_count,
            worker_count=workers,
            bucket_index_source=bucket_index_source,
            selection_mode=selection_mode,
            policy_scan_skipped_reason="compatibility_option_not_applied",
            notification_detail_mode=self.s3_notification_detail_mode,
        )
        capped = self.s3_notification_scan_summary.limited
        partial = bool(error_count or bucket_index_limitations)
        limitations = list(bucket_index_limitations)
        if capped:
            limitations.append("S3 notification evidence was bounded by the configured operational bucket cap.")
        if error_count:
            limitations.append("One or more S3 bucket notification reads failed.")
        self.collection_summary = LambdaCostCycleCollectionSummary(
            s3_notification_detail_mode=self.s3_notification_detail_mode,
            bucket_population_known=True,
            bucket_population_count=(self.s3_notification_scan_summary.candidate_bucket_count),
            bucket_notifications_attempted=len(task_results),
            notification_success_count=success_count,
            notification_failure_count=error_count,
            collection_complete=not capped and not partial,
            collection_capped=capped,
            collection_partial=partial,
            operational_bucket_cap=self.max_s3_buckets,
            limitations=tuple(limitations),
        )
        return records

    def _build_s3_notification_tasks(
        self,
        buckets: list[dict[str, object]],
    ) -> list[AwsCollectionTask[list[S3LambdaNotificationRecord]]]:
        tasks: list[AwsCollectionTask[list[S3LambdaNotificationRecord]]] = []
        for bucket in buckets:
            bucket_name = str(bucket.get("Name") or "")
            if not bucket_name:
                continue
            bucket_region = normalized_s3_bucket_region(bucket)
            tasks.append(
                AwsCollectionTask(
                    name=(f"LambdaCostCycleS3NotificationCollector:s3:GetBucketNotificationConfiguration:{bucket_name}"),
                    scanner_id=self.audit_context.scanner_id,
                    collector_id="LambdaCostCycleS3NotificationCollector",
                    account_id=self.account_id,
                    region=bucket_region,
                    service="s3",
                    operation="GetBucketNotificationConfiguration",
                    payload={"bucket_name": bucket_name},
                    collect=self._build_s3_notification_collector(
                        bucket_name,
                        bucket_region,
                    ),
                ),
            )
        return tasks

    def _build_s3_notification_collector(
        self,
        bucket_name: str,
        bucket_region: str | None,
    ) -> Callable[[], list[S3LambdaNotificationRecord]]:
        return lambda: self._collect_bucket_lambda_notifications(
            bucket_name,
            bucket_region,
        )

    def _collect_bucket_lambda_notifications(
        self,
        bucket_name: str,
        bucket_region: str | None,
    ) -> list[S3LambdaNotificationRecord]:
        if not bucket_name:
            return []
        client = self.session.create_client(
            "s3",
            region_name=bucket_region or "us-east-1",
            audit_context=self.audit_context,
        )
        response = client.get_bucket_notification_configuration(
            Bucket=bucket_name,
        )
        records: list[S3LambdaNotificationRecord] = [
            S3LambdaNotificationRecord(
                bucket_name=bucket_name,
                lambda_function_arn=str(config.get("LambdaFunctionArn") or ""),
                events=[str(item) for item in config.get("Events", [])],
                filter_rules=extract_s3_filter_rules(config),
            )
            for config in response.get("LambdaFunctionConfigurations", [])
        ]
        return records

    def _select_s3_buckets_for_notification_scan(
        self,
        buckets: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        selection = self._s3_notification_bucket_selector.select_buckets(
            buckets,
            summary=self.s3_notification_scan_summary,
        )
        self.s3_notification_scan_summary = selection.summary
        return selection.buckets

    def _bucket_is_in_selected_region_scope(self, bucket: dict[str, object]) -> bool:
        return self._s3_notification_bucket_selector.bucket_is_in_selected_region_scope(
            bucket,
        )
