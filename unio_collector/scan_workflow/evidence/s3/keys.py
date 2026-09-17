from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.s3 import (
        S3BucketIdentity,
        S3LifecycleCollectionOptions,
    )


@dataclass(frozen=True)
class S3EvidenceCacheKeyBuilder:
    """Builds stable same-scan cache keys for shared S3 evidence."""

    account_id: str

    def build_bucket_index_key(  # noqa: D102
        self,
        *,
        selected_regions: list[str],
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            tuple(selected_regions),
        )

    def build_lifecycle_inventory_key(  # noqa: D102
        self,
        *,
        buckets: tuple[S3BucketIdentity, ...],
        max_buckets: int,
        collection_options: S3LifecycleCollectionOptions,
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            tuple(bucket.bucket_name for bucket in buckets),
            max_buckets,
            collection_options.convert_to_cache_key(),
        )

    def build_multipart_inventory_key(  # noqa: D102
        self,
        *,
        buckets: tuple[S3BucketIdentity, ...],
        max_buckets: int,
        max_multipart_uploads_per_bucket: int,
        max_multipart_buckets: int,
        multipart_bucket_selection_mode: str,
        skip_buckets_with_abort_incomplete_rule: bool,
        lifecycle_collection_options: S3LifecycleCollectionOptions,
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            tuple(bucket.bucket_name for bucket in buckets),
            max_buckets,
            max_multipart_uploads_per_bucket,
            max_multipart_buckets,
            multipart_bucket_selection_mode,
            skip_buckets_with_abort_incomplete_rule,
            lifecycle_collection_options.convert_to_cache_key(),
        )

    def build_bucket_metadata_key(  # noqa: D102
        self,
        *,
        bucket: S3BucketIdentity,
        metadata_type: str,
    ) -> tuple[object, ...]:
        return (
            self.account_id,
            bucket.bucket_name,
            bucket.region,
            metadata_type,
        )
