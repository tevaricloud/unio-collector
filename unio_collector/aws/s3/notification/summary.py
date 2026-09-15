from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class S3NotificationScanSummary:  # noqa: D101
    candidate_bucket_count: int = 0
    checked_bucket_count: int = 0
    skipped_bucket_count: int = 0
    max_s3_buckets: int | None = None
    worker_count: int = 4
    notification_read_error_count: int = 0
    limited: bool = False
    bucket_index_source: str = "direct_list_buckets"
    selection_mode: str = "bucket_cap"
    policy_scan_max_functions: int = 50
    policy_function_count: int = 0
    policy_candidate_bucket_count: int = 0
    policy_read_error_count: int = 0
    policy_scan_skipped_reason: str | None = None
    policy_baseline_bucket_check_count: int = 0
    policy_minimum_bucket_check_count: int = 0
    notification_detail_mode: str = "full"

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "candidate_bucket_count": self.candidate_bucket_count,
            "checked_bucket_count": self.checked_bucket_count,
            "skipped_bucket_count": self.skipped_bucket_count,
            "max_s3_buckets": self.max_s3_buckets,
            "worker_count": self.worker_count,
            "notification_read_error_count": self.notification_read_error_count,
            "limited": self.limited,
            "bucket_index_source": self.bucket_index_source,
            "selection_mode": self.selection_mode,
            "policy_scan_max_functions": self.policy_scan_max_functions,
            "policy_function_count": self.policy_function_count,
            "policy_candidate_bucket_count": self.policy_candidate_bucket_count,
            "policy_read_error_count": self.policy_read_error_count,
            "policy_scan_skipped_reason": self.policy_scan_skipped_reason,
            "policy_baseline_bucket_check_count": (self.policy_baseline_bucket_check_count),
            "policy_minimum_bucket_check_count": (self.policy_minimum_bucket_check_count),
            "notification_detail_mode": self.notification_detail_mode,
        }
