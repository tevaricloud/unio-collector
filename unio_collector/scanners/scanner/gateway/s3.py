from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.s3 import (
        S3BucketIndexResult,
        S3LifecycleCollectionOptions,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.gateway.protocols import ScannerS3GatewayRuntime


@dataclass(frozen=True)
class ScannerS3Gateway:  # noqa: D101
    runtime: ScannerS3GatewayRuntime
    definition: ScannerDefinition

    def collect_lifecycle_records(  # noqa: D102
        self,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> Any:  # noqa: ANN401
        return self.runtime.collect_cached_s3_lifecycle_records(
            self.definition,
            max_buckets=max_buckets,
            max_bucket_workers=max_bucket_workers,
            collection_options=collection_options,
        )

    def collect_multipart_records(  # noqa: D102
        self,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        max_multipart_uploads_per_bucket: int,
        skip_buckets_with_abort_incomplete_rule: bool,
        max_multipart_buckets: int = 0,
        multipart_bucket_selection_mode: str = "inventory-order",
        lifecycle_collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> Any:  # noqa: ANN401
        return self.runtime.collect_cached_s3_multipart_records(
            self.definition,
            max_buckets=max_buckets,
            max_bucket_workers=max_bucket_workers,
            max_multipart_uploads_per_bucket=max_multipart_uploads_per_bucket,
            skip_buckets_with_abort_incomplete_rule=(skip_buckets_with_abort_incomplete_rule),
            max_multipart_buckets=max_multipart_buckets,
            multipart_bucket_selection_mode=multipart_bucket_selection_mode,
            lifecycle_collection_options=lifecycle_collection_options,
        )

    def collect_bucket_index(self, *, max_bucket_workers: int) -> S3BucketIndexResult:  # noqa: D102
        return self.runtime.collect_cached_s3_bucket_index(
            self.definition,
            max_bucket_workers=max_bucket_workers,
        )
