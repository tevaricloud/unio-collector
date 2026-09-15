from __future__ import annotations  # noqa: D100

from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.s3.lifecycle.record import S3BucketLifecycleRecord

EXPECTED_S3_ABSENCE_CODES = frozenset(
    {
        "NoSuchLifecycleConfiguration",
        "NoSuchTagSet",
        "ReplicationConfigurationNotFoundError",
        "NoSuchBucket",
    },
)

S3_LIFECYCLE_DETAIL_MODES = frozenset({"full", "prioritized"})
S3_MULTIPART_BUCKET_SELECTION_MODES = frozenset(
    {"inventory-order", "storage-prioritized"},
)


def normalize_s3_location(value: Any) -> str:  # noqa: ANN401, D103
    if value in (None, ""):
        return "us-east-1"
    if value == "EU":
        return "eu-west-1"
    return str(value)


def normalize_collection_profile(value: object) -> str:  # noqa: D103
    profile = str(value or "full").strip().lower().replace("_", "-")
    if profile in {"full", "standard", "fast-dev"}:
        return profile
    msg = "S3 lifecycle collection_profile must be one of 'full', 'standard', or 'fast-dev'."
    raise ValueError(
        msg,
    )


def normalize_s3_lifecycle_detail_mode(value: object) -> str:  # noqa: D103
    mode = str(value or "full").strip().lower().replace("_", "-")
    if mode in S3_LIFECYCLE_DETAIL_MODES:
        return mode
    allowed = "', '".join(sorted(S3_LIFECYCLE_DETAIL_MODES))
    msg = f"S3 lifecycle lifecycle_detail_mode must be one of '{allowed}'."
    raise ValueError(msg)


def normalize_s3_multipart_bucket_selection_mode(value: object) -> str:  # noqa: D103
    mode = str(value or "inventory-order").strip().lower().replace("_", "-")
    if mode in S3_MULTIPART_BUCKET_SELECTION_MODES:
        return mode
    allowed = "', '".join(sorted(S3_MULTIPART_BUCKET_SELECTION_MODES))
    msg = f"S3 multipart_bucket_selection_mode must be one of '{allowed}'."
    raise ValueError(msg)


def summarize_lifecycle_rules(rules: Any) -> list[dict[str, Any]]:  # noqa: ANN401, D103
    if not isinstance(rules, list):
        return []
    summaries: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        summaries.append(
            {
                "id": rule.get("ID"),
                "status": rule.get("Status"),
                "has_filter": bool(rule.get("Filter")),
                "has_expiration": bool(rule.get("Expiration")),
                "has_transition": bool(rule.get("Transitions")),
                "has_noncurrent_version_expiration": bool(
                    rule.get("NoncurrentVersionExpiration"),
                ),
                "has_noncurrent_version_transition": bool(
                    rule.get("NoncurrentVersionTransitions"),
                ),
                "has_abort_incomplete_multipart_upload": bool(
                    rule.get("AbortIncompleteMultipartUpload"),
                ),
                "has_current_version_expiration": bool(rule.get("Expiration")),
                "has_current_version_transition": bool(rule.get("Transitions")),
            },
        )
    return summaries


def summarize_replication_rules(rules: Any) -> list[dict[str, Any]]:  # noqa: ANN401, D103
    if not isinstance(rules, list):
        return []
    summaries: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        destination = rule.get("Destination")
        if not isinstance(destination, dict):
            destination = {}
        delete_marker = rule.get("DeleteMarkerReplication")
        if not isinstance(delete_marker, dict):
            delete_marker = {}
        replication_time = destination.get("ReplicationTime")
        if not isinstance(replication_time, dict):
            replication_time = {}
        metrics = destination.get("Metrics")
        if not isinstance(metrics, dict):
            metrics = {}
        summaries.append(
            {
                "id": rule.get("ID"),
                "status": rule.get("Status"),
                "priority": rule.get("Priority"),
                "has_filter": bool(rule.get("Filter")),
                "destination_bucket": destination.get("Bucket"),
                "destination_storage_class": destination.get("StorageClass"),
                "delete_marker_replication_status": delete_marker.get("Status"),
                "replication_time_status": replication_time.get("Status"),
                "metrics_status": metrics.get("Status"),
            },
        )
    return summaries


def count_rule_status(rules: list[dict[str, Any]], status: str) -> int:  # noqa: D103
    return sum(1 for rule in rules if str(rule.get("status") or "").lower() == status.lower())


def count_conditional_versioning_skips(  # noqa: D103
    records: list[S3BucketLifecycleRecord],
) -> int:
    return sum(1 for record in records if record.bucket_versioning_skip_reason is not None)


def count_prioritized_lifecycle_skips(  # noqa: D103
    records: list[S3BucketLifecycleRecord],
) -> int:
    return sum(1 for record in records if (not record.bucket_lifecycle_collected and record.bucket_lifecycle_skip_reason is not None))


def count_lifecycle_metric_unknown_records(  # noqa: D103
    records: list[S3BucketLifecycleRecord],
) -> int:
    return sum(
        1 for record in records if (not record.lifecycle_priority_metric_collected and record.bucket_size_bytes is None and record.bucket_object_count is None)
    )


def has_enabled_replication(rules: Any) -> bool:  # noqa: ANN401, D103
    if not isinstance(rules, list):
        return False
    return any(isinstance(rule, dict) and rule.get("Status") == "Enabled" for rule in rules)


def collect_replication_destinations(rules: Any) -> list[str]:  # noqa: ANN401, D103
    if not isinstance(rules, list):
        return []
    destinations: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("Status") != "Enabled":
            continue
        destination = rule.get("Destination")
        if isinstance(destination, dict) and destination.get("Bucket"):
            destinations.append(str(destination["Bucket"]))
    return sorted(set(destinations))


def find_oldest_upload_initiated(  # noqa: D103
    uploads: list[dict[str, Any]],
) -> datetime | None:
    initiated_values: list[datetime] = []
    for upload in uploads:
        value = upload.get("Initiated")
        if isinstance(value, datetime):
            initiated_values.append(value)
    return min(initiated_values) if initiated_values else None


def tags_to_dict(tags: list[dict[str, Any]]) -> dict[str, str]:  # noqa: D103
    return {str(tag.get("Key")): str(tag.get("Value")) for tag in tags if tag.get("Key")}
