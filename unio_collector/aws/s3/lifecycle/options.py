from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.aws.s3.helpers import (
    normalize_collection_profile,
    normalize_s3_lifecycle_detail_mode,
)


@dataclass(frozen=True)
class S3LifecycleCollectionOptions:
    """Controls optional S3 bucket metadata calls for one scan run."""

    collection_profile: str = "full"
    collect_tags: bool = True
    collect_versioning: bool = True
    collect_replication: bool = True
    conditional_versioning_collection: bool = False
    lifecycle_detail_mode: str = "full"
    prioritized_lifecycle_bucket_count: int = 25
    include_lifecycle_metric_unknown_buckets: bool = True

    @classmethod
    def from_profile(  # noqa: D102
        cls,
        profile: object = "full",
        *,
        collect_tags: bool | None = None,
        collect_versioning: bool | None = None,
        collect_replication: bool | None = None,
        conditional_versioning_collection: bool | None = None,
        lifecycle_detail_mode: object | None = None,
        prioritized_lifecycle_bucket_count: int | None = None,
        include_lifecycle_metric_unknown_buckets: bool | None = None,
    ) -> S3LifecycleCollectionOptions:
        profile_name = normalize_collection_profile(profile)
        defaults = {
            "full": {
                "collect_tags": True,
                "collect_versioning": True,
                "collect_replication": True,
                "conditional_versioning_collection": False,
                "lifecycle_detail_mode": "full",
                "prioritized_lifecycle_bucket_count": 25,
                "include_lifecycle_metric_unknown_buckets": True,
            },
            "standard": {
                "collect_tags": True,
                "collect_versioning": True,
                "collect_replication": False,
                "conditional_versioning_collection": False,
                "lifecycle_detail_mode": "full",
                "prioritized_lifecycle_bucket_count": 25,
                "include_lifecycle_metric_unknown_buckets": True,
            },
            "fast-dev": {
                "collect_tags": False,
                "collect_versioning": True,
                "collect_replication": False,
                "conditional_versioning_collection": True,
                "lifecycle_detail_mode": "full",
                "prioritized_lifecycle_bucket_count": 25,
                "include_lifecycle_metric_unknown_buckets": True,
            },
        }[profile_name]
        return cls(
            collection_profile=profile_name,
            collect_tags=(defaults["collect_tags"] if collect_tags is None else collect_tags),
            collect_versioning=(defaults["collect_versioning"] if collect_versioning is None else collect_versioning),
            collect_replication=(defaults["collect_replication"] if collect_replication is None else collect_replication),
            conditional_versioning_collection=(
                bool(defaults["conditional_versioning_collection"]) if conditional_versioning_collection is None else conditional_versioning_collection
            ),
            lifecycle_detail_mode=normalize_s3_lifecycle_detail_mode(
                defaults["lifecycle_detail_mode"] if lifecycle_detail_mode is None else lifecycle_detail_mode,
            ),
            prioritized_lifecycle_bucket_count=max(
                1,
                int(
                    defaults["prioritized_lifecycle_bucket_count"] if prioritized_lifecycle_bucket_count is None else prioritized_lifecycle_bucket_count,
                ),
            ),
            include_lifecycle_metric_unknown_buckets=(
                bool(defaults["include_lifecycle_metric_unknown_buckets"])
                if include_lifecycle_metric_unknown_buckets is None
                else include_lifecycle_metric_unknown_buckets
            ),
        )

    def convert_to_cache_key(self) -> tuple[object, ...]:  # noqa: D102
        return (
            self.collection_profile,
            self.collect_tags,
            self.collect_versioning,
            self.collect_replication,
            self.conditional_versioning_collection,
            self.lifecycle_detail_mode,
            self.prioritized_lifecycle_bucket_count,
            self.include_lifecycle_metric_unknown_buckets,
        )

    def get_skipped_metadata(self) -> list[str]:  # noqa: D102
        skipped: list[str] = []
        if not self.collect_tags:
            skipped.append("bucket_tags")
        if not self.collect_versioning:
            skipped.append("bucket_versioning")
        if not self.collect_replication:
            skipped.append("bucket_replication")
        return skipped

    def get_collected_metadata(self) -> list[str]:  # noqa: D102
        collected = ["bucket_lifecycle"]
        if self.collect_tags:
            collected.append("bucket_tags")
        if self.collect_versioning:
            collected.append("bucket_versioning")
        if self.collect_replication:
            collected.append("bucket_replication")
        return collected

    def should_collect_versioning_conditionally(self) -> bool:
        """Return the active collection behavior for the compatibility option."""
        return False

    def get_operational_detail_cap(self) -> int | None:
        """Resolve the neutral detail cap from legacy profile option names."""
        if self.lifecycle_detail_mode != "prioritized":
            return None
        return self.prioritized_lifecycle_bucket_count
