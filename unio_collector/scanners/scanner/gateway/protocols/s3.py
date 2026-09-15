from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.s3 import S3BucketIndexResult, S3LifecycleCollectionOptions
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerS3GatewayRuntime(Protocol):
    """Runtime capabilities required by scanner S3 gateways."""

    def collect_cached_s3_lifecycle_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        max_buckets: int,
        max_bucket_workers: int,
        collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> object: ...

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
    ) -> object: ...

    def collect_cached_s3_bucket_index(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        max_bucket_workers: int,
    ) -> S3BucketIndexResult: ...
