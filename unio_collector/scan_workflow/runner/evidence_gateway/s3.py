from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.s3 import S3BucketIndexResult, S3LifecycleCollectionOptions
    from unio_collector.scan_workflow.runner.evidence_gateway.protocols import (
        S3EvidenceSource,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class S3EvidenceGateway:
    """Delegate S3 evidence collection to the S3 evidence source."""

    def __init__(self, source: S3EvidenceSource) -> None:  # noqa: D107
        self._source = source

    def collect_cached_s3_lifecycle_records(
        self,
        definition: ScannerDefinition,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> object:
        """Return cached S3 lifecycle inventory evidence for a scanner."""
        return self._source.collect_cached_s3_lifecycle_records(
            definition,
            max_buckets=max_buckets,
            max_bucket_workers=max_bucket_workers,
            collection_options=collection_options,
        )

    def collect_cached_s3_multipart_records(
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
    ) -> object:
        """Return cached S3 multipart-upload evidence with lifecycle context."""
        return self._source.collect_cached_s3_multipart_records(
            definition,
            max_buckets=max_buckets,
            max_bucket_workers=max_bucket_workers,
            max_multipart_uploads_per_bucket=max_multipart_uploads_per_bucket,
            max_multipart_buckets=max_multipart_buckets,
            multipart_bucket_selection_mode=multipart_bucket_selection_mode,
            skip_buckets_with_abort_incomplete_rule=(skip_buckets_with_abort_incomplete_rule),
            lifecycle_collection_options=lifecycle_collection_options,
        )

    def collect_cached_s3_bucket_index(
        self,
        definition: ScannerDefinition,
        *,
        max_bucket_workers: int,
    ) -> S3BucketIndexResult:
        """Return cached S3 bucket index evidence for scanner reuse."""
        return self._source.collect_cached_s3_bucket_index(
            definition,
            max_bucket_workers=max_bucket_workers,
        )
