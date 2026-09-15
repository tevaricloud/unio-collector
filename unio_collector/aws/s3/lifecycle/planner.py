from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.aws.s3.metadata import S3BucketMetadataResult

if TYPE_CHECKING:
    from unio_collector.aws.s3.identity import S3BucketIdentity
    from unio_collector.aws.s3.lifecycle.options import S3LifecycleCollectionOptions


@dataclass(frozen=True)
class S3LifecycleMetadataPlanner:
    """Apply a stable operational bound to lifecycle detail collection.

    The historical class name is retained for import compatibility. Storage
    ranking, empty-bucket exclusion, and finding-aware versioning decisions are
    analyzer policy and are intentionally absent here.
    """

    collection_options: S3LifecycleCollectionOptions

    def select_detail_buckets(  # noqa: D102
        self,
        buckets: list[S3BucketIdentity],
    ) -> list[S3BucketIdentity]:
        ordered = sorted(buckets, key=lambda bucket: bucket.bucket_name)
        operational_cap = self.collection_options.get_operational_detail_cap()
        if operational_cap is None or len(ordered) <= operational_cap:
            return ordered
        return ordered[:operational_cap]

    def mark_operationally_capped_metadata(  # noqa: D102
        self,
        buckets: list[S3BucketIdentity],
        *,
        detail_buckets: list[S3BucketIdentity],
        metadata_by_bucket: dict[str, dict[str, S3BucketMetadataResult]],
    ) -> None:
        retained_names = {bucket.bucket_name for bucket in detail_buckets}
        for bucket in buckets:
            if bucket.bucket_name in retained_names:
                continue
            metadata_by_type = metadata_by_bucket.setdefault(bucket.bucket_name, {})
            for metadata_type, enabled in (
                ("tags", self.collection_options.collect_tags),
                ("lifecycle", True),
                ("versioning", self.collection_options.collect_versioning),
                ("replication", self.collection_options.collect_replication),
            ):
                if enabled:
                    metadata_by_type[metadata_type] = S3BucketMetadataResult(
                        bucket_name=bucket.bucket_name,
                        metadata_type=metadata_type,
                        collected=False,
                        limitation=("S3 bucket metadata was not collected because the neutral lifecycle detail operational cap bound."),
                    )

    def mark_prioritized_skipped_metadata(
        self,
        buckets: list[S3BucketIdentity],
        *,
        detail_buckets: list[S3BucketIdentity],
        metadata_by_bucket: dict[str, dict[str, S3BucketMetadataResult]],
    ) -> None:
        """Compatibility alias for the former policy-oriented method."""
        self.mark_operationally_capped_metadata(
            buckets,
            detail_buckets=detail_buckets,
            metadata_by_bucket=metadata_by_bucket,
        )


__all__ = ["S3LifecycleMetadataPlanner"]
