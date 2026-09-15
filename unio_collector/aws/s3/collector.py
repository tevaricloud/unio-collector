from __future__ import annotations  # noqa: D100

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    record_collection_results,
)
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.s3.bucket.collection import S3BucketCollectionResult
from unio_collector.aws.s3.bucket.index import S3BucketIndexResult
from unio_collector.aws.s3.buckets import S3BucketCollectionMixin
from unio_collector.aws.s3.coverage_notes import S3BucketCoverageNoteBuilder
from unio_collector.aws.s3.identity import S3BucketIdentity
from unio_collector.aws.s3.lifecycle.collection import S3LifecycleCollectionMixin
from unio_collector.aws.s3.lifecycle.collection_summary import (
    S3LifecycleCollectionSummary,
)
from unio_collector.aws.s3.lifecycle.options import S3LifecycleCollectionOptions
from unio_collector.aws.s3.lifecycle.planner import S3LifecycleMetadataPlanner
from unio_collector.aws.s3.metadata import S3BucketMetadataResult
from unio_collector.aws.s3.multipart.bucket_context import S3MultipartBucketContext
from unio_collector.aws.s3.multipart.collection_summary import (
    S3MultipartCollectionSummary,
)
from unio_collector.aws.s3.multipart.selector import S3MultipartBucketSelector
from unio_collector.aws.s3.records import S3RecordCollectionMixin

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.s3.lifecycle.record import S3BucketLifecycleRecord
    from unio_collector.aws.s3.multipart.upload import S3MultipartUploadRecord
    from unio_collector.aws.s3.storage_metric import S3BucketStorageMetric

S3BucketMetadataCacheLoader = Callable[
    [S3BucketIdentity, str, Callable[[], S3BucketMetadataResult]],
    S3BucketMetadataResult,
]


class S3InventoryCollector(
    S3LifecycleCollectionMixin,
    S3BucketCollectionMixin,
    S3RecordCollectionMixin,
):
    """Collect read-only S3 lifecycle, versioning, replication, and upload state."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
        max_multipart_uploads_per_bucket: int = 1000,
        max_bucket_workers: int | None = None,
        metadata_cache_loader: S3BucketMetadataCacheLoader | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = set(selected_regions or [])
        self.max_multipart_uploads_per_bucket = max(
            1,
            max_multipart_uploads_per_bucket,
        )
        self.max_bucket_workers = max(1, max_bucket_workers or self._get_max_workers())
        self.metadata_cache_loader = metadata_cache_loader
        self._pagination = AwsPaginationHelper()
        self._client_cache: dict[str, Any] = {}
        self._client_cache_lock = threading.Lock()
        self._coverage_notes = S3BucketCoverageNoteBuilder(
            scanner_id=self.audit_context.scanner_id,
            max_bucket_workers=self.max_bucket_workers,
        )
        self._multipart_bucket_selector = S3MultipartBucketSelector(
            note_builder=self._coverage_notes,
        )

    def collect_bucket_cost_records(self) -> S3BucketCollectionResult:  # noqa: D102
        return self._collect_bucket_records(
            bucket_index=None,
            include_lifecycle=True,
            include_multipart=True,
            max_buckets=0,
            lifecycle_collection_options=S3LifecycleCollectionOptions(),
        )

    def collect_lifecycle_records(  # noqa: D102
        self,
        *,
        bucket_index: S3BucketIndexResult | None = None,
        max_buckets: int = 0,
        collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> S3BucketCollectionResult:
        return self._collect_bucket_records(
            bucket_index=bucket_index,
            include_lifecycle=True,
            include_multipart=False,
            max_buckets=max_buckets,
            lifecycle_collection_options=(collection_options or S3LifecycleCollectionOptions()),
        )

    def collect_multipart_records(  # noqa: D102
        self,
        *,
        bucket_index: S3BucketIndexResult | None = None,
        lifecycle_records: list[S3BucketLifecycleRecord] | None = None,
        skip_buckets_with_abort_incomplete_rule: bool = False,
        max_buckets: int = 0,
        max_multipart_buckets: int = 0,
        multipart_bucket_selection_mode: object = "inventory-order",
    ) -> S3BucketCollectionResult:
        return self._collect_bucket_records(
            bucket_index=bucket_index,
            lifecycle_records=lifecycle_records,
            skip_buckets_with_abort_incomplete_rule=skip_buckets_with_abort_incomplete_rule,
            include_lifecycle=False,
            include_multipart=True,
            max_buckets=max_buckets,
            max_multipart_buckets=max_multipart_buckets,
            multipart_bucket_selection_mode=multipart_bucket_selection_mode,
            lifecycle_collection_options=S3LifecycleCollectionOptions(),
        )

    def collect_bucket_index(self) -> S3BucketIndexResult:  # noqa: D102
        buckets = sorted(
            self._list_buckets(),
            key=lambda item: str(item.get("Name") or ""),
        )
        direct_identities, unresolved_buckets = self._build_bucket_identities_from_list_metadata(buckets)
        identities_by_name = {identity.bucket_name: identity for identity in direct_identities}
        regional_result = self._collect_selected_region_bucket_identities(
            unresolved_buckets,
        )
        identities_by_name.update(
            {identity.bucket_name: identity for identity in regional_result.identities},
        )
        fallback_buckets = self._get_location_fallback_buckets(
            unresolved_buckets,
            identities_by_name=identities_by_name,
            regional_lookup_complete=regional_result.regional_lookup_complete,
        )
        tasks = self._build_bucket_identity_tasks(fallback_buckets)
        task_results = AwsCollectionExecutor(
            max_workers=self.max_bucket_workers,
        ).run(tasks)
        record_collection_results(self.session, task_results)

        selected_buckets: list[S3BucketIdentity] = []
        warnings: list[str] = []
        for result in task_results:
            if result.status != "completed":
                warnings.append(
                    f"Could not collect S3 bucket location for {result.task.payload.get('bucket_name')}: {result.error_code or result.status}.",
                )
                continue
            if result.value is None:
                continue
            if result.value.warning:
                warnings.append(result.value.warning)
            identities_by_name[result.value.bucket_name] = result.value
        for bucket in buckets:
            bucket_name = str(bucket.get("Name") or "")
            identity = identities_by_name.get(bucket_name)
            if identity is None:
                continue
            if self.selected_regions and identity.region not in self.selected_regions:
                continue
            selected_buckets.append(identity)
        regions = sorted({bucket.region for bucket in selected_buckets})
        return S3BucketIndexResult(
            buckets=selected_buckets,
            regions=regions,
            discovered_bucket_count=len(buckets),
            selected_bucket_count=len(selected_buckets),
            warnings=warnings,
        )

    def _collect_bucket_records(
        self,
        *,
        bucket_index: S3BucketIndexResult | None,
        lifecycle_records: list[S3BucketLifecycleRecord] | None = None,
        skip_buckets_with_abort_incomplete_rule: bool = False,
        include_lifecycle: bool,
        include_multipart: bool,
        max_buckets: int,
        lifecycle_collection_options: S3LifecycleCollectionOptions,
        max_multipart_buckets: int = 0,
        multipart_bucket_selection_mode: object = "inventory-order",
    ) -> S3BucketCollectionResult:
        del skip_buckets_with_abort_incomplete_rule
        bucket_index = bucket_index or self.collect_bucket_index()
        limited_buckets, coverage_notes = self._limit_bucket_index(
            bucket_index,
            max_buckets=max_buckets,
            collection_options=lifecycle_collection_options,
        )
        collected_lifecycle_records = (
            self._collect_lifecycle_records(
                limited_buckets,
                collection_options=lifecycle_collection_options,
            )
            if include_lifecycle
            else list(lifecycle_records or [])
        )
        lifecycle_summary = (
            self._build_lifecycle_collection_summary(
                population=limited_buckets,
                population_count=bucket_index.selected_bucket_count,
                max_buckets=max_buckets,
                records=collected_lifecycle_records,
                collection_options=lifecycle_collection_options,
                index_partial=bool(bucket_index.warnings),
            )
            if include_lifecycle
            else None
        )
        multipart_buckets: list[S3BucketIdentity] = []
        multipart_coverage_notes: list[dict[str, Any]] = []
        if include_multipart:
            multipart_buckets, multipart_coverage_notes = self._limit_multipart_buckets(
                limited_buckets,
                max_multipart_buckets=max_multipart_buckets,
                lifecycle_records=collected_lifecycle_records,
                multipart_bucket_selection_mode=multipart_bucket_selection_mode,
            )
        multipart_records = self._collect_multipart_records(multipart_buckets) if include_multipart else []
        multipart_contexts = (
            self._build_multipart_bucket_contexts(
                limited_buckets,
                lifecycle_records=collected_lifecycle_records,
            )
            if include_multipart
            else []
        )
        multipart_summary = (
            self._build_multipart_collection_summary(
                population=limited_buckets,
                population_count=bucket_index.selected_bucket_count,
                max_buckets=max_buckets,
                retained=multipart_buckets,
                records=multipart_records,
                max_multipart_buckets=max_multipart_buckets,
                index_partial=bool(bucket_index.warnings),
            )
            if include_multipart
            else None
        )
        return S3BucketCollectionResult(
            lifecycle_records=collected_lifecycle_records if include_lifecycle else [],
            multipart_records=multipart_records,
            regions=sorted({bucket.region for bucket in limited_buckets}),
            warnings=list(bucket_index.warnings),
            coverage_notes=[
                *coverage_notes,
                *multipart_coverage_notes,
                *self._build_execution_notes(
                    include_lifecycle=include_lifecycle,
                    include_multipart=include_multipart,
                    lifecycle_bucket_count=len(limited_buckets),
                    lifecycle_region_count=len(
                        {bucket.region for bucket in limited_buckets},
                    ),
                    multipart_bucket_count=len(multipart_buckets),
                    collection_options=lifecycle_collection_options,
                    conditional_versioning_skipped_count=0,
                    prioritized_lifecycle_skipped_count=(
                        len(limited_buckets) - (lifecycle_summary.retained_bucket_count if lifecycle_summary else len(limited_buckets))
                    ),
                    lifecycle_metric_unknown_count=0,
                ),
            ],
            discovered_bucket_count=bucket_index.discovered_bucket_count,
            selected_bucket_count=bucket_index.selected_bucket_count,
            evaluated_bucket_count=len(limited_buckets),
            lifecycle_collection_summary=lifecycle_summary,
            multipart_collection_summary=multipart_summary,
            multipart_bucket_contexts=multipart_contexts,
        )

    def _collect_lifecycle_records(
        self,
        buckets: list[S3BucketIdentity],
        *,
        collection_options: S3LifecycleCollectionOptions,
    ) -> list[S3BucketLifecycleRecord]:
        storage_metrics_by_bucket = self._collect_storage_metrics(
            buckets,
            collection_options=collection_options,
        )
        metadata_planner = S3LifecycleMetadataPlanner(
            collection_options=collection_options,
        )
        detail_buckets = metadata_planner.select_detail_buckets(buckets)
        metadata_by_bucket = self._collect_lifecycle_metadata_by_bucket(
            detail_buckets,
            collection_options=collection_options,
        )
        metadata_planner.mark_operationally_capped_metadata(
            buckets,
            detail_buckets=detail_buckets,
            metadata_by_bucket=metadata_by_bucket,
        )
        return [
            self._build_lifecycle_record_from_metadata(
                bucket,
                collection_options=collection_options,
                metadata_by_type=metadata_by_bucket.get(bucket.bucket_name, {}),
                storage_metric=storage_metrics_by_bucket.get(bucket.bucket_name),
            )
            for bucket in buckets
        ]

    def _collect_storage_metrics(
        self,
        buckets: list[S3BucketIdentity],
        *,
        collection_options: S3LifecycleCollectionOptions,
    ) -> dict[str, S3BucketStorageMetric]:
        if collection_options.lifecycle_detail_mode != "prioritized" or not buckets:
            return {}
        metrics_by_bucket: dict[str, S3BucketStorageMetric] = {}
        for region, region_buckets in self._group_buckets_by_region(buckets).items():
            metrics_by_bucket.update(
                self._collect_storage_metrics_for_region(
                    region,
                    region_buckets,
                ),
            )
        return metrics_by_bucket

    def _build_lifecycle_collection_summary(
        self,
        *,
        population: list[S3BucketIdentity],
        population_count: int,
        max_buckets: int,
        records: list[S3BucketLifecycleRecord],
        collection_options: S3LifecycleCollectionOptions,
        index_partial: bool,
    ) -> S3LifecycleCollectionSummary:
        cap = collection_options.get_operational_detail_cap()
        retained_count = min(len(population), cap) if cap is not None else len(population)
        outer_cap_bound = len(population) < population_count
        cap_bound = retained_count < len(population)
        by_name = {record.bucket_name: record for record in records}

        def counts(
            attribute: str,
            *,
            enabled: bool,
        ) -> tuple[int, int, int, int]:
            attempted = retained_count if enabled else 0
            succeeded = sum(bool(getattr(by_name.get(bucket.bucket_name), attribute, False)) for bucket in population[:retained_count])
            return attempted, succeeded, attempted - succeeded, population_count - attempted

        lifecycle = counts("bucket_lifecycle_collected", enabled=True)
        versioning = counts(
            "bucket_versioning_collected",
            enabled=collection_options.collect_versioning,
        )
        tagging = counts(
            "bucket_tags_collected",
            enabled=collection_options.collect_tags,
        )
        replication = counts(
            "bucket_replication_collected",
            enabled=collection_options.collect_replication,
        )
        failure_count = lifecycle[2] + versioning[2] + tagging[2] + replication[2]
        limitations: list[str] = []
        if cap_bound or outer_cap_bound:
            limitations.append("Lifecycle detail collection was bounded by its neutral operational cap.")
        if failure_count:
            limitations.append("One or more configured S3 metadata reads did not complete successfully.")
        if index_partial:
            limitations.append("One or more S3 bucket identity reads did not complete successfully.")
        return S3LifecycleCollectionSummary(
            bucket_population_known=True,
            bucket_population_count=population_count,
            retained_bucket_count=retained_count,
            operational_outer_cap=max_buckets if max_buckets > 0 else None,
            outer_cap_bound=outer_cap_bound,
            operational_detail_cap=cap,
            cap_bound=cap_bound,
            lifecycle_reads_attempted=lifecycle[0],
            lifecycle_reads_succeeded=lifecycle[1],
            lifecycle_reads_failed=lifecycle[2],
            versioning_reads_attempted=versioning[0],
            versioning_reads_succeeded=versioning[1],
            versioning_reads_failed=versioning[2],
            versioning_not_collected=versioning[3],
            tagging_reads_attempted=tagging[0],
            tagging_reads_succeeded=tagging[1],
            tagging_reads_failed=tagging[2],
            tagging_not_collected=tagging[3],
            replication_reads_attempted=replication[0],
            replication_reads_succeeded=replication[1],
            replication_reads_failed=replication[2],
            replication_not_collected=replication[3],
            collection_complete=not cap_bound and not outer_cap_bound and failure_count == 0 and not index_partial,
            collection_capped=cap_bound or outer_cap_bound,
            collection_partial=failure_count > 0 or index_partial,
            region_count=len({bucket.region for bucket in population}),
            worker_count=self.max_bucket_workers,
            limitations=tuple(limitations),
        )

    def _build_multipart_bucket_contexts(
        self,
        buckets: list[S3BucketIdentity],
        *,
        lifecycle_records: list[S3BucketLifecycleRecord],
    ) -> list[S3MultipartBucketContext]:
        by_name = {record.bucket_name: record for record in lifecycle_records}
        contexts: list[S3MultipartBucketContext] = []
        for bucket in sorted(buckets, key=lambda item: item.bucket_name):
            record = by_name.get(bucket.bucket_name)
            lifecycle_known = bool(record and record.bucket_lifecycle_collected)
            metric_known = bool(record and record.lifecycle_priority_metric_collected)
            contexts.append(
                S3MultipartBucketContext(
                    bucket_name=bucket.bucket_name,
                    lifecycle_context_known=lifecycle_known,
                    abort_incomplete_upload_rule=(record.has_abort_incomplete_multipart_upload if lifecycle_known and record is not None else None),
                    storage_metric_known=metric_known,
                    object_count=record.bucket_object_count if record else None,
                    size_bytes=record.bucket_size_bytes if record else None,
                ),
            )
        return contexts

    def _build_multipart_collection_summary(
        self,
        *,
        population: list[S3BucketIdentity],
        population_count: int,
        max_buckets: int,
        retained: list[S3BucketIdentity],
        records: list[S3MultipartUploadRecord],
        max_multipart_buckets: int,
        index_partial: bool,
    ) -> S3MultipartCollectionSummary:
        outer_cap_bound = len(population) < population_count
        cap_bound = len(retained) < len(population)
        failure_count = len(retained) - len(records) + sum(bool(record.limitations) for record in records)
        pagination_capped = sum(not record.pagination_complete and not record.limitations for record in records)
        succeeded = sum(not record.limitations for record in records)
        limitations: list[str] = []
        if cap_bound or outer_cap_bound:
            limitations.append("Multipart collection was bounded by its neutral operational bucket cap.")
        if failure_count:
            limitations.append("One or more ListMultipartUploads reads did not complete successfully.")
        if index_partial:
            limitations.append("One or more S3 bucket identity reads did not complete successfully.")
        if pagination_capped:
            limitations.append("One or more bucket upload inventories reached the per-bucket pagination bound.")
        return S3MultipartCollectionSummary(
            bucket_population_known=True,
            bucket_population_count=population_count,
            retained_bucket_count=len(retained),
            operational_outer_cap=max_buckets if max_buckets > 0 else None,
            outer_cap_bound=outer_cap_bound,
            operational_bucket_cap=(max_multipart_buckets if max_multipart_buckets > 0 else None),
            cap_bound=cap_bound,
            list_uploads_attempted=len(retained),
            list_uploads_succeeded=succeeded,
            list_uploads_failed=failure_count,
            pagination_complete_bucket_count=len(records) - pagination_capped,
            pagination_capped_bucket_count=pagination_capped,
            collection_complete=not cap_bound and not outer_cap_bound and failure_count == 0 and pagination_capped == 0 and not index_partial,
            collection_capped=cap_bound or outer_cap_bound or pagination_capped > 0,
            collection_partial=failure_count > 0 or index_partial,
            region_count=len({bucket.region for bucket in retained}),
            worker_count=self.max_bucket_workers,
            max_uploads_per_bucket=self.max_multipart_uploads_per_bucket,
            limitations=tuple(limitations),
        )
