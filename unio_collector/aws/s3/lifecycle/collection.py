# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    AwsCollectionTaskResult,
    record_collection_results,
)
from unio_collector.aws.metric.request import MetricRequest
from unio_collector.aws.s3.identity import S3BucketIdentity
from unio_collector.aws.s3.metadata import S3BucketMetadataResult
from unio_collector.aws.s3.storage_metric import S3BucketStorageMetric

if TYPE_CHECKING:
    from unio_collector.aws.s3.lifecycle.options import S3LifecycleCollectionOptions

S3BucketMetadataCacheLoader = Callable[
    [S3BucketIdentity, str, Callable[[], S3BucketMetadataResult]],
    S3BucketMetadataResult,
]


class S3LifecycleCollectionMixin:  # noqa: D101
    def _collect_storage_metrics_for_region(
        self,
        region: str,
        buckets: list[S3BucketIdentity],
    ) -> dict[str, S3BucketStorageMetric]:
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(days=3)
        requests: list[MetricRequest] = []
        request_context: list[tuple[str, str]] = []
        for bucket in buckets:
            requests.append(
                MetricRequest(
                    namespace="AWS/S3",
                    metric_name="NumberOfObjects",
                    dimensions=[
                        {"Name": "BucketName", "Value": bucket.bucket_name},
                        {"Name": "StorageType", "Value": "AllStorageTypes"},
                    ],
                    statistic="Average",
                    period=86400,
                    start_time=start_time,
                    end_time=end_time,
                ),
            )
            request_context.append((bucket.bucket_name, "object_count"))
            requests.append(
                MetricRequest(
                    namespace="AWS/S3",
                    metric_name="BucketSizeBytes",
                    dimensions=[
                        {"Name": "BucketName", "Value": bucket.bucket_name},
                        {"Name": "StorageType", "Value": "StandardStorage"},
                    ],
                    statistic="Average",
                    period=86400,
                    start_time=start_time,
                    end_time=end_time,
                ),
            )
            request_context.append((bucket.bucket_name, "size_bytes"))
        collector = CloudWatchMetricCollector(
            self.session,
            region=region,
            audit_context=self.audit_context,
        )
        summaries = collector.collect_metric_summaries(requests)
        values_by_bucket: dict[str, dict[str, int | None]] = {bucket.bucket_name: {"object_count": None, "size_bytes": None} for bucket in buckets}
        limitations_by_bucket: dict[str, list[str]] = {bucket.bucket_name: [] for bucket in buckets}
        for (bucket_name, metric_type), summary in zip(
            request_context,
            summaries,
            strict=True,
        ):
            value = summary.observed_max or summary.observed_average
            if value is None:
                if summary.limitation:
                    limitations_by_bucket[bucket_name].append(summary.limitation)
                continue
            values_by_bucket[bucket_name][metric_type] = max(0, int(value))
        return {
            bucket_name: S3BucketStorageMetric(
                bucket_name=bucket_name,
                object_count=values.get("object_count"),
                size_bytes=values.get("size_bytes"),
                metric_collected=(values.get("object_count") is not None or values.get("size_bytes") is not None),
                limitation=("; ".join(sorted(set(limitations_by_bucket[bucket_name]))) if limitations_by_bucket[bucket_name] else None),
            )
            for bucket_name, values in values_by_bucket.items()
        }

    def _collect_lifecycle_metadata_by_bucket(
        self,
        buckets: list[S3BucketIdentity],
        *,
        collection_options: S3LifecycleCollectionOptions,
    ) -> dict[str, dict[str, S3BucketMetadataResult]]:
        results = self._collect_lifecycle_metadata_results(
            buckets,
            collection_options=collection_options,
        )
        return self._group_lifecycle_metadata_results(results)

    def _collect_lifecycle_metadata_results(
        self,
        buckets: list[S3BucketIdentity],
        *,
        collection_options: S3LifecycleCollectionOptions,
    ) -> list[AwsCollectionTaskResult[S3BucketMetadataResult]]:
        buckets_by_region = self._group_buckets_by_region(buckets)
        if len(buckets_by_region) <= 1:
            return self._collect_lifecycle_metadata_results_for_buckets(
                buckets,
                collection_options=collection_options,
            )
        worker_count = min(len(buckets_by_region), self._get_max_workers())
        results: list[AwsCollectionTaskResult[S3BucketMetadataResult]] = []
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="unio-collector-s3-metadata-region",
        ) as executor:
            futures = [
                executor.submit(
                    self._collect_lifecycle_metadata_results_for_buckets,
                    region_buckets,
                    collection_options=collection_options,
                )
                for region_buckets in buckets_by_region.values()
            ]
            for future in as_completed(futures):
                results.extend(future.result())
        return results

    def _collect_lifecycle_metadata_results_for_buckets(
        self,
        buckets: list[S3BucketIdentity],
        *,
        collection_options: S3LifecycleCollectionOptions,
    ) -> list[AwsCollectionTaskResult[S3BucketMetadataResult]]:
        tasks = self._build_lifecycle_metadata_tasks(
            buckets,
            collection_options=collection_options,
        )
        if not tasks:
            return []
        results = AwsCollectionExecutor(
            max_workers=min(self.max_bucket_workers, len(tasks)),
        ).run(tasks)
        record_collection_results(self.session, results)
        return results

    def _group_buckets_by_region(
        self,
        buckets: list[S3BucketIdentity],
    ) -> dict[str, list[S3BucketIdentity]]:
        grouped: dict[str, list[S3BucketIdentity]] = {}
        for bucket in buckets:
            grouped.setdefault(bucket.region, []).append(bucket)
        return grouped

    def _build_lifecycle_metadata_tasks(
        self,
        buckets: list[S3BucketIdentity],
        *,
        collection_options: S3LifecycleCollectionOptions,
    ) -> list[AwsCollectionTask[S3BucketMetadataResult]]:
        tasks: list[AwsCollectionTask[S3BucketMetadataResult]] = []
        for bucket in buckets:
            if collection_options.collect_tags:
                tasks.append(
                    self._build_lifecycle_metadata_task(
                        bucket,
                        operation="GetBucketTagging",
                        metadata_type="tags",
                        collect=lambda bucket=bucket: self._collect_cached_metadata(
                            bucket,
                            "tags",
                            lambda: self._collect_tag_metadata(bucket),
                        ),
                    ),
                )
            tasks.append(
                self._build_lifecycle_metadata_task(
                    bucket,
                    operation="GetBucketLifecycleConfiguration",
                    metadata_type="lifecycle",
                    collect=lambda bucket=bucket: self._collect_cached_metadata(
                        bucket,
                        "lifecycle",
                        lambda: self._collect_optional_metadata(
                            bucket,
                            metadata_type="lifecycle",
                            method_name="get_bucket_lifecycle_configuration",
                            absent_codes={"NoSuchLifecycleConfiguration"},
                        ),
                    ),
                ),
            )
            if collection_options.collect_versioning:
                tasks.append(
                    self._build_lifecycle_metadata_task(
                        bucket,
                        operation="GetBucketVersioning",
                        metadata_type="versioning",
                        collect=lambda bucket=bucket: self._collect_cached_metadata(
                            bucket,
                            "versioning",
                            lambda: self._collect_optional_metadata(
                                bucket,
                                metadata_type="versioning",
                                method_name="get_bucket_versioning",
                                absent_codes=set(),
                            ),
                        ),
                    ),
                )
            if collection_options.collect_replication:
                tasks.append(
                    self._build_lifecycle_metadata_task(
                        bucket,
                        operation="GetBucketReplication",
                        metadata_type="replication",
                        collect=lambda bucket=bucket: self._collect_cached_metadata(
                            bucket,
                            "replication",
                            lambda: self._collect_optional_metadata(
                                bucket,
                                metadata_type="replication",
                                method_name="get_bucket_replication",
                                absent_codes={"ReplicationConfigurationNotFoundError"},
                            ),
                        ),
                    ),
                )
        return tasks

    def _collect_cached_metadata(
        self,
        bucket: S3BucketIdentity,
        metadata_type: str,
        collect: Callable[[], S3BucketMetadataResult],
    ) -> S3BucketMetadataResult:
        if self.metadata_cache_loader is None:
            return collect()
        return self.metadata_cache_loader(bucket, metadata_type, collect)

    def _build_lifecycle_metadata_task(
        self,
        bucket: S3BucketIdentity,
        *,
        operation: str,
        metadata_type: str,
        collect: Callable[[], S3BucketMetadataResult],
    ) -> AwsCollectionTask[S3BucketMetadataResult]:
        return AwsCollectionTask(
            name=(f"S3InventoryCollector:lifecycle:{operation}:{bucket.bucket_name}"),
            scanner_id=self.audit_context.scanner_id,
            collector_id=self.audit_context.collector,
            account_id=self.account_id,
            region=bucket.region,
            service="s3",
            operation=operation,
            payload={
                "bucket_name": bucket.bucket_name,
                "metadata_type": metadata_type,
            },
            collect=collect,
        )

    def _group_lifecycle_metadata_results(
        self,
        results: list[AwsCollectionTaskResult[S3BucketMetadataResult]],
    ) -> dict[str, dict[str, S3BucketMetadataResult]]:
        grouped: dict[str, dict[str, S3BucketMetadataResult]] = {}
        for result in results:
            bucket_name = str(result.task.payload.get("bucket_name") or "")
            metadata_type = str(result.task.payload.get("metadata_type") or "")
            if not bucket_name or not metadata_type:
                continue
            metadata = result.value
            if result.status != "completed" or metadata is None:
                metadata = S3BucketMetadataResult(
                    bucket_name=bucket_name,
                    metadata_type=metadata_type,
                    collected=False,
                    limitation=(f"Could not collect {metadata_type} metadata: {result.error_code or result.status}."),
                )
            grouped.setdefault(bucket_name, {})[metadata_type] = metadata
        return grouped
