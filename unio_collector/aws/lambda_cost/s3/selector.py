from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from unio_collector.aws.s3.notification.selection import (
    S3NotificationBucketSelection,
)
from unio_collector.aws.s3.notification.summary import S3NotificationScanSummary
from unio_collector.aws.serverless.inventory_helpers import normalized_s3_bucket_region

if TYPE_CHECKING:
    from unio_collector.aws.s3 import S3BucketIdentity


@dataclass(frozen=True)
class LambdaS3NotificationBucketSelector:
    """Apply deterministic scope and operational bounds to S3 buckets."""

    selected_regions: list[str] | None
    max_s3_buckets: int | None
    worker_count: int
    policy_scan_max_functions: int
    notification_detail_mode: str

    def build_summary_skipped_by_detail_mode(self) -> S3NotificationScanSummary:  # noqa: D102
        return S3NotificationScanSummary(
            max_s3_buckets=self.max_s3_buckets,
            worker_count=self.worker_count,
            policy_scan_max_functions=self.policy_scan_max_functions,
            bucket_index_source="not_collected",
            selection_mode="summary_skipped",
            policy_scan_skipped_reason="skipped_by_notification_detail_mode",
            notification_detail_mode=self.notification_detail_mode,
        )

    def build_bucket_candidate(  # noqa: D102
        self,
        bucket: S3BucketIdentity,
    ) -> dict[str, object]:
        candidate: dict[str, object] = {
            "Name": bucket.bucket_name,
            "BucketRegion": bucket.region,
            "BucketArn": bucket.arn,
        }
        if bucket.creation_date is not None:
            candidate["CreationDate"] = bucket.creation_date
        return candidate

    def estimate_notification_check_count(  # noqa: D102
        self,
        buckets: list[dict[str, object]],
    ) -> int:
        scoped_bucket_count = sum(1 for bucket in buckets if self.bucket_is_in_selected_region_scope(bucket))
        if self.max_s3_buckets is None:
            return scoped_bucket_count
        return min(scoped_bucket_count, self.max_s3_buckets)

    def select_buckets(  # noqa: D102
        self,
        buckets: list[dict[str, object]],
        *,
        summary: S3NotificationScanSummary,
    ) -> S3NotificationBucketSelection:
        scoped_buckets = [bucket for bucket in buckets if self.bucket_is_in_selected_region_scope(bucket)]
        sorted_buckets = sorted(
            scoped_buckets,
            key=lambda bucket: (
                self.get_bucket_region_rank(bucket),
                str(bucket.get("Name") or ""),
            ),
        )
        selected = sorted_buckets if self.max_s3_buckets is None else sorted_buckets[: self.max_s3_buckets]
        skipped_count = max(0, len(sorted_buckets) - len(selected))
        return S3NotificationBucketSelection(
            buckets=selected,
            summary=replace(
                summary,
                candidate_bucket_count=len(sorted_buckets),
                checked_bucket_count=len(selected),
                skipped_bucket_count=skipped_count,
                max_s3_buckets=self.max_s3_buckets,
                worker_count=self.worker_count,
                limited=skipped_count > 0,
                notification_detail_mode=self.notification_detail_mode,
            ),
        )

    def get_bucket_region_rank(self, bucket: dict[str, object]) -> int:  # noqa: D102
        if not self.selected_regions:
            return 0
        bucket_region = normalized_s3_bucket_region(bucket)
        if bucket_region in set(self.selected_regions):
            return 0
        if not bucket_region:
            return 1
        return 2

    def bucket_is_in_selected_region_scope(  # noqa: D102
        self,
        bucket: dict[str, object],
    ) -> bool:
        if not self.selected_regions:
            return True
        bucket_region = normalized_s3_bucket_region(bucket)
        if not bucket_region:
            return True
        return bucket_region in set(self.selected_regions)
