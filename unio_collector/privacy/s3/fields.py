"""Explicit privacy fields for S3 public-access, lifecycle and multipart evidence."""

from __future__ import annotations

Spec = tuple[str, str, bool]


def fields(names: str, kind: str, category: str = "safe_metadata", *, nullable: bool = False) -> dict[str, Spec]:
    """Expand only an explicit reviewed field list, never provider-observed keys."""
    return dict.fromkeys(names.split(), (kind, category, nullable))


PUBLIC: dict[str, Spec] = {
    "": ("object", "safe_metadata", False),
    **fields("account_id", "string", "aws_account_id"),
    **fields("account_public_access_block buckets[].public_access_block", "object", nullable=True),
    **fields("buckets[]", "object"),
    **fields("buckets warnings", "array"),
    **fields("buckets[].bucket_name", "string", "bucket_name"),
    **fields("account_public_access_block_status", "string", "free_text"),
    **fields("account_public_access_block_error_code", "string", "free_text", nullable=True),
    **fields("warnings[]", "string", "free_text"),
    **fields("buckets[].policy_is_public buckets[].acl_is_public", "boolean", nullable=True),
    **{
        prefix + key: ("boolean", "safe_metadata", False)
        for prefix in ("account_public_access_block.", "buckets[].public_access_block.")
        for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    },
}
COMMON: dict[str, Spec] = {
    "": ("object", "safe_metadata", False),
    **fields("records regions warnings", "array"),
    **fields("records[]", "object"),
    **fields("collection_summary", "object", nullable=True),
    **fields("regions[]", "string", "region"),
    **fields("warnings[] records[].limitations[] collection_summary.limitations[]", "string", "free_text"),
    **fields("records[].limitations collection_summary.limitations", "array"),
    **fields("records[].bucket_name", "string", "bucket_name"),
    **fields("records[].account_id", "string", "aws_account_id"),
    **fields("records[].region", "string", "region"),
    **fields("records[].arn", "string", "arn"),
    **fields("selection_policy_applied", "boolean"),
    **fields("historical_selection_mode", "string", "free_text"),
    **fields("historical_bucket_limit records[].regional_cost_record_count", "count"),
    **fields("records[].service_current_cost records[].service_previous_cost records[].regional_current_cost", "money", "cost", nullable=True),
    **fields("records[].service_cost_currency records[].regional_cost_currency", "string", "cost", nullable=True),
    **fields(
        (
            "collection_summary.bucket_population_known collection_summary.outer_cap_bound "
            "collection_summary.cap_bound collection_summary.collection_complete collection_summary.collection_capped "
            "collection_summary.collection_partial collection_summary.collection_unavailable "
            "collection_summary.collection_skipped"
        ),
        "boolean",
    ),
    **fields(
        ("collection_summary.bucket_population_count collection_summary.retained_bucket_count collection_summary.region_count collection_summary.worker_count"),
        "count",
    ),
    **fields("collection_summary.operational_outer_cap", "count", nullable=True),
}
LIFECYCLE: dict[str, Spec] = {
    **COMMON,
    **fields("historical_include_metric_unknown historical_conditional_versioning", "boolean"),
    **fields("records[].creation_date", "timestamp", "timestamp", nullable=True),
    **fields("records[].collection_profile records[].skipped_metadata[]", "string", "free_text"),
    **fields(
        ("records[].skipped_metadata records[].lifecycle_rule_summaries records[].replication_rule_summaries records[].replication_destinations"), "array"
    ),
    "records[].tags": ("tag_map", "tag_value", False),
    **fields(
        (
            "records[].bucket_tags_collected records[].bucket_lifecycle_collected "
            "records[].lifecycle_priority_metric_collected records[].has_lifecycle_policy "
            "records[].bucket_versioning_collected records[].has_noncurrent_version_expiration "
            "records[].has_noncurrent_version_transition records[].has_current_version_expiration "
            "records[].has_current_version_transition records[].has_abort_incomplete_multipart_upload "
            "records[].bucket_replication_collected records[].replication_enabled"
        ),
        "boolean",
    ),
    **fields(
        "records[].bucket_lifecycle_skip_reason records[].bucket_versioning_skip_reason records[].versioning_status", "string", "free_text", nullable=True
    ),
    **fields("records[].bucket_size_bytes records[].bucket_object_count", "count", nullable=True),
    **fields(
        (
            "records[].lifecycle_rule_count records[].enabled_lifecycle_rule_count "
            "records[].disabled_lifecycle_rule_count records[].replication_rule_count "
            "records[].enabled_replication_rule_count"
        ),
        "count",
    ),
    **fields("records[].lifecycle_rule_summaries[] records[].replication_rule_summaries[]", "object"),
    **fields("records[].lifecycle_rule_summaries[].id records[].replication_rule_summaries[].id", "string", "resource_id", nullable=True),
    **fields(
        (
            "records[].lifecycle_rule_summaries[].status records[].replication_rule_summaries[].status "
            "records[].replication_rule_summaries[].destination_storage_class "
            "records[].replication_rule_summaries[].delete_marker_replication_status "
            "records[].replication_rule_summaries[].replication_time_status "
            "records[].replication_rule_summaries[].metrics_status"
        ),
        "string",
        "free_text",
        nullable=True,
    ),
    **fields("records[].replication_rule_summaries[].priority", "count", nullable=True),
    **fields("records[].replication_rule_summaries[].destination_bucket records[].replication_destinations[]", "string", "arn", nullable=True),
    **{
        f"records[].lifecycle_rule_summaries[].{key}": ("boolean", "safe_metadata", False)
        for key in (
            "has_filter",
            "has_expiration",
            "has_transition",
            "has_noncurrent_version_expiration",
            "has_noncurrent_version_transition",
            "has_abort_incomplete_multipart_upload",
            "has_current_version_expiration",
            "has_current_version_transition",
        )
    },
    **fields("records[].replication_rule_summaries[].has_filter", "boolean"),
    **fields("collection_summary.operational_detail_cap", "count", nullable=True),
    **{
        f"collection_summary.{key}": ("count", "safe_metadata", False)
        for key in (
            "lifecycle_reads_attempted",
            "lifecycle_reads_succeeded",
            "lifecycle_reads_failed",
            "versioning_reads_attempted",
            "versioning_reads_succeeded",
            "versioning_reads_failed",
            "versioning_not_collected",
            "tagging_reads_attempted",
            "tagging_reads_succeeded",
            "tagging_reads_failed",
            "tagging_not_collected",
            "replication_reads_attempted",
            "replication_reads_succeeded",
            "replication_reads_failed",
            "replication_not_collected",
        )
    },
}
MULTIPART: dict[str, Spec] = {
    **COMMON,
    **fields("historical_skip_abort_rule_buckets records[].pagination_complete", "boolean"),
    **fields("records[].upload_count records[].page_count", "count"),
    **fields("records[].oldest_initiated", "timestamp", "timestamp", nullable=True),
    **fields("records[].sample_keys", "array"),
    **fields("records[].sample_keys[]", "string", "resource_name"),
    **fields("bucket_contexts", "array"),
    **fields("bucket_contexts[]", "object"),
    **fields("bucket_contexts[].bucket_name", "string", "bucket_name"),
    **fields("bucket_contexts[].lifecycle_context_known bucket_contexts[].storage_metric_known", "boolean"),
    **fields("bucket_contexts[].abort_incomplete_upload_rule", "boolean", nullable=True),
    **fields("bucket_contexts[].object_count bucket_contexts[].size_bytes collection_summary.operational_bucket_cap", "count", nullable=True),
    **fields(
        (
            "collection_summary.list_uploads_attempted collection_summary.list_uploads_succeeded "
            "collection_summary.list_uploads_failed collection_summary.pagination_complete_bucket_count "
            "collection_summary.pagination_capped_bucket_count collection_summary.max_uploads_per_bucket"
        ),
        "count",
    ),
}
PUBLIC_LITERALS = {
    "account_public_access_block_error_code": {
        "AccessDenied",
        "ServiceUnavailable",
        "UnsupportedOperation",
        "InternalFailure",
        "NoSuchPublicAccessBlockConfiguration",
        "ValueError",
    },
    "account_public_access_block_status": {"unknown", "not_configured", "unavailable", "configured"},
    "historical_selection_mode": {"full", "prioritized", "inventory-order", "storage-prioritized"},
    "records[].collection_profile": {"full", "standard", "fast-dev"},
    "records[].versioning_status": {"Enabled", "Suspended"},
    "records[].skipped_metadata[]": {"tags", "versioning", "replication", "priority_metrics"},
    "records[].lifecycle_rule_summaries[].status": {"Enabled", "Disabled"},
    "records[].replication_rule_summaries[].status": {"Enabled", "Disabled"},
    "records[].replication_rule_summaries[].delete_marker_replication_status": {"Enabled", "Disabled"},
    "records[].replication_rule_summaries[].replication_time_status": {"Enabled", "Disabled"},
    "records[].replication_rule_summaries[].metrics_status": {"Enabled", "Disabled"},
    "records[].replication_rule_summaries[].destination_storage_class": {
        "STANDARD",
        "REDUCED_REDUNDANCY",
        "STANDARD_IA",
        "ONEZONE_IA",
        "INTELLIGENT_TIERING",
        "GLACIER",
        "DEEP_ARCHIVE",
        "OUTPOSTS",
        "GLACIER_IR",
        "SNOW",
        "EXPRESS_ONEZONE",
        "FSX_OPENZFS",
    },
}
