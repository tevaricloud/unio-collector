from __future__ import annotations  # noqa: D104

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from unio_collector.aws.s3 import (
    S3BucketCollectionResult,
    S3BucketIdentity,
    S3BucketIndexResult,
    S3BucketMetadataResult,
    S3InventoryCollector,
    S3LifecycleCollectionOptions,
)
from unio_collector.scan_workflow.evidence.s3.keys import S3EvidenceCacheKeyBuilder
from unio_collector.scan_workflow.evidence.s3.notes import (
    S3EvidenceCoverageNoteBuilder,
    format_s3_bucket_metadata_label,
)
from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.cache import AwsScanCacheAccess
    from unio_collector.scanners.scanner.definition import ScannerDefinition

SHARED_S3_BUCKET_INDEX_CONSUMERS = frozenset(
    {
        "lambda-cost-cycle-risk-review",
        "s3-lifecycle-cost-review",
        "s3-versioning-and-replication-review",
        "s3-incomplete-multipart-review",
    },
)
SHARED_S3_BUCKET_INDEX_SCANNER_ID = "unio-collector-shared-s3-bucket-index"
SHARED_S3_BUCKET_INDEX_API_CALLS = (
    "s3:ListBuckets",
    "s3:GetBucketLocation",
)


class S3EvidenceMixin(EvidenceCollectionBase):  # noqa: D101
    def build_s3_cache_keys(self) -> S3EvidenceCacheKeyBuilder:  # noqa: D102
        return S3EvidenceCacheKeyBuilder(
            account_id=str(self.runner.runtime_state.account_id),
        )

    def build_s3_coverage_notes(self) -> S3EvidenceCoverageNoteBuilder:  # noqa: D102
        return S3EvidenceCoverageNoteBuilder()

    def collect_cached_s3_lifecycle_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> S3BucketCollectionResult:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="s3_lifecycle_inventory",
            label="S3 bucket lifecycle/versioning metadata",
        )
        resolved_options = collection_options or S3LifecycleCollectionOptions()
        collector = self.create_s3_collector(
            definition,
            max_bucket_workers=max_bucket_workers,
        )
        bucket_index = self._collect_cached_s3_bucket_index_with_collector(
            definition,
            collector,
        )
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "s3_lifecycle_inventory",
            self.build_s3_cache_keys().build_lifecycle_inventory_key(
                buckets=tuple(bucket_index.buckets),
                max_buckets=max_buckets,
                collection_options=resolved_options,
            ),
            lambda: collector.collect_lifecycle_records(
                bucket_index=bucket_index,
                max_buckets=max_buckets,
                collection_options=resolved_options,
            ),
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="s3_lifecycle_inventory",
            label="S3 bucket lifecycle/versioning metadata",
            access_status=access.status,
        )
        return self.build_s3_lifecycle_consumer_result(
            definition,
            access=access,
            collection_options=resolved_options,
        )

    def collect_cached_s3_multipart_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        max_multipart_uploads_per_bucket: int,
        skip_buckets_with_abort_incomplete_rule: bool,
        max_multipart_buckets: int = 0,
        multipart_bucket_selection_mode: str = "inventory-order",
        lifecycle_collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> S3BucketCollectionResult:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="s3_multipart_inventory",
            label="S3 incomplete multipart upload metadata",
        )
        resolved_lifecycle_options = lifecycle_collection_options or S3LifecycleCollectionOptions()
        collector = self.create_s3_collector(
            definition,
            max_bucket_workers=max_bucket_workers,
            max_multipart_uploads_per_bucket=max_multipart_uploads_per_bucket,
        )
        bucket_index = self._collect_cached_s3_bucket_index_with_collector(
            definition,
            collector,
        )
        lifecycle_records = []
        needs_lifecycle_records = skip_buckets_with_abort_incomplete_rule or multipart_bucket_selection_mode == "storage-prioritized"
        if needs_lifecycle_records:
            cache = self.runner.runtime_state.cache
            lifecycle_access = cache.get_existing_with_status(
                "s3_lifecycle_inventory",
                self.build_s3_cache_keys().build_lifecycle_inventory_key(
                    buckets=tuple(bucket_index.buckets),
                    max_buckets=max_buckets,
                    collection_options=resolved_lifecycle_options,
                ),
                access_policy=self.build_cache_access_policy(
                    consumer_id=definition.scanner_id,
                ),
            )
            if lifecycle_access is not None:
                lifecycle_records = list(lifecycle_access.value.lifecycle_records)
                self.add_cached_evidence_note(
                    definition,
                    namespace="s3_lifecycle_inventory",
                    label="S3 bucket lifecycle/versioning metadata",
                    access_status=lifecycle_access.status,
                )
            self.add_multipart_lifecycle_dependency_note(
                definition,
                lifecycle_available=lifecycle_access is not None,
            )
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "s3_multipart_inventory",
            self.build_s3_cache_keys().build_multipart_inventory_key(
                buckets=tuple(bucket_index.buckets),
                max_buckets=max_buckets,
                max_multipart_uploads_per_bucket=max_multipart_uploads_per_bucket,
                max_multipart_buckets=max_multipart_buckets,
                multipart_bucket_selection_mode=multipart_bucket_selection_mode,
                skip_buckets_with_abort_incomplete_rule=(skip_buckets_with_abort_incomplete_rule),
                lifecycle_collection_options=resolved_lifecycle_options,
            ),
            lambda: collector.collect_multipart_records(
                bucket_index=bucket_index,
                lifecycle_records=lifecycle_records,
                skip_buckets_with_abort_incomplete_rule=(skip_buckets_with_abort_incomplete_rule),
                max_buckets=max_buckets,
                max_multipart_buckets=max_multipart_buckets,
                multipart_bucket_selection_mode=multipart_bucket_selection_mode,
            ),
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="s3_multipart_inventory",
            label="S3 incomplete multipart upload metadata",
            access_status=access.status,
        )
        return replace(
            access.value,
            coverage_notes=(
                self.build_s3_coverage_notes().build_multipart_collection_notes(
                    summary=access.value.multipart_collection_summary,
                )
            ),
        )

    def add_multipart_lifecycle_dependency_note(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        lifecycle_available: bool,
    ) -> None:
        self.runner.add_scanner_coverage_note(
            definition.scanner_id,
            self.build_s3_coverage_notes().build_multipart_lifecycle_dependency_note(
                lifecycle_available=lifecycle_available,
            ),
        )

    def collect_cached_s3_bucket_index(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        max_bucket_workers: int,
    ) -> S3BucketIndexResult:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="s3_bucket_index",
            label="S3 bucket identity and region inventory",
        )
        collector = self.create_s3_collector(
            definition,
            max_bucket_workers=max_bucket_workers,
        )
        return self._collect_cached_s3_bucket_index_with_collector(
            definition,
            collector,
        )

    def _collect_cached_s3_bucket_index_with_collector(
        self,
        definition: ScannerDefinition,
        collector: S3InventoryCollector,
    ) -> S3BucketIndexResult:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="s3_bucket_index",
            label="S3 bucket identity and region inventory",
        )
        selected_regions = self.runner.runtime_state.get_selected_regions() or []
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "s3_bucket_index",
            self.build_s3_cache_keys().build_bucket_index_key(
                selected_regions=selected_regions,
            ),
            collector.collect_bucket_index,
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="s3_bucket_index",
            label="S3 bucket identity and region inventory",
            access_status=access.status,
        )
        return access.value

    def create_s3_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        max_bucket_workers: int,
        max_multipart_uploads_per_bucket: int = 1000,
    ) -> S3InventoryCollector:
        runtime_state = self.runner.runtime_state
        return S3InventoryCollector(
            runtime_state.session,
            account_id=runtime_state.account_id,
            audit_context=self.runner.create_audit_context(
                definition,
                "S3InventoryCollector",
            ),
            selected_regions=runtime_state.get_selected_regions(),
            max_bucket_workers=max_bucket_workers,
            max_multipart_uploads_per_bucket=max_multipart_uploads_per_bucket,
            metadata_cache_loader=(
                lambda bucket, metadata_type, loader: self.collect_cached_s3_bucket_metadata(
                    definition,
                    bucket,
                    metadata_type,
                    loader,
                )
            ),
        )

    def build_s3_lifecycle_consumer_result(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        access: AwsScanCacheAccess[S3BucketCollectionResult],
        collection_options: S3LifecycleCollectionOptions,
    ) -> S3BucketCollectionResult:
        collection_notes = self.build_s3_coverage_notes().build_lifecycle_collection_notes(
            definition=definition,
            summary=access.value.lifecycle_collection_summary,
            collection_options=collection_options,
        )
        if access.status == "loaded":
            return replace(access.value, coverage_notes=collection_notes)
        return replace(
            access.value,
            coverage_notes=[
                *collection_notes,
                *self.build_reused_s3_lifecycle_coverage_notes(
                    definition,
                    collection_options=collection_options,
                    access_status=access.status,
                ),
            ],
        )

    def build_reused_s3_lifecycle_coverage_notes(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        collection_options: S3LifecycleCollectionOptions,
        access_status: str,
    ) -> list[dict[str, Any]]:
        return self.build_s3_coverage_notes().build_reused_lifecycle_notes(
            definition=definition,
            collection_options=collection_options,
            access_status=access_status,
        )

    def collect_cached_s3_bucket_metadata(  # noqa: D102
        self,
        definition: ScannerDefinition,
        bucket: S3BucketIdentity,
        metadata_type: str,
        loader: Callable[[], S3BucketMetadataResult],
    ) -> S3BucketMetadataResult:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="s3_bucket_metadata",
            label=format_s3_bucket_metadata_label(metadata_type),
        )
        access = self.runner.runtime_state.cache.get_or_load_with_status(
            "s3_bucket_metadata",
            self.build_s3_cache_keys().build_bucket_metadata_key(
                bucket=bucket,
                metadata_type=metadata_type,
            ),
            loader,
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="s3_bucket_metadata",
            label=format_s3_bucket_metadata_label(metadata_type),
            access_status=access.status,
        )
        return access.value
