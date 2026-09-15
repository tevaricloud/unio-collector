from __future__ import annotations  # noqa: D100


def get_known_scanner_option_names(scanner_id: str) -> frozenset[str]:
    """Return configured option names independently of profile ownership."""
    return frozenset(SCANNER_OPTION_NAMES.get(scanner_id, ()))


SCANNER_OPTION_NAMES: dict[str, tuple[str, ...]] = {
    "api-gateway-cost-review": ("vpc_link_detail_mode",),
    "backup-retention-review": (
        "collect_tags",
        "long_retention_days",
        "max_detail_workers",
        "older_than_days",
        "selection_detail_mode",
    ),
    "billing-alerts-and-budgets-review": (
        "monitor_detail_mode",
        "subscriber_detail_mode",
    ),
    "cloudfront-origin-cost-review": ("invalidation_detail_mode",),
    "cloudwatch-idle-log-review": (
        "idle_days",
        "max_metric_log_groups",
        "max_metric_log_groups_per_region",
        "metric_detail_mode",
        "metric_prioritization_scope",
    ),
    "cloudwatch-log-cost-and-relevance-review": (
        "max_metric_log_groups",
        "max_metric_log_groups_per_region",
        "metric_detail_mode",
        "metric_prioritization_scope",
    ),
    "config-cost-governance-review": ("rule_detail_mode",),
    "dynamodb-cost-governance-review": (
        "autoscaling_detail_mode",
        "max_table_workers",
        "metric_detail_mode",
        "retention_detail_mode",
        "table_detail_regional_mode",
    ),
    "ec2-idle-instance-review": (
        "max_instances_per_region",
        "scheduled_shutdown",
    ),
    "ecs-cost-governance-review": (
        "regional_collection_mode",
        "task_definition_detail_mode",
    ),
    "elasticache-cost-review": ("metric_detail_mode",),
    "iam-account-security-review": ("policy_detail_mode",),
    "lambda-cost-cycle-risk-review": (
        "collect_tags",
        "max_s3_buckets",
        "s3_notification_detail_mode",
        "s3_notification_worker_count",
        "s3_policy_scan_max_functions",
    ),
    "load-balancer-idle-review": (
        "collect_tags",
        "target_health_detail_mode",
    ),
    "network-vpc-flow-log-attribution": (
        "max_log_groups_per_region",
        "poll_seconds",
        "query_limit",
        "query_timeout_seconds",
    ),
    "rds-snapshot-retention-review": ("older_than_days",),
    "s3-incomplete-multipart-review": (
        "max_bucket_workers",
        "max_buckets",
        "max_multipart_buckets",
        "max_multipart_uploads_per_bucket",
        "multipart_bucket_selection_mode",
        "skip_buckets_with_abort_incomplete_rule",
    ),
    "s3-lifecycle-cost-review": (
        "collect_replication",
        "collect_tags",
        "collection_profile",
        "conditional_versioning_collection",
        "include_lifecycle_metric_unknown_buckets",
        "lifecycle_detail_mode",
        "max_bucket_workers",
        "max_buckets",
        "prioritized_lifecycle_bucket_count",
    ),
    "s3-versioning-and-replication-review": (
        "collect_replication",
        "collect_tags",
        "collection_profile",
        "conditional_versioning_collection",
        "include_lifecycle_metric_unknown_buckets",
        "lifecycle_detail_mode",
        "max_bucket_workers",
        "max_buckets",
        "prioritized_lifecycle_bucket_count",
    ),
    "service-quota-proximity-review": (
        "remaining_threshold",
        "threshold_percent",
    ),
    "snapshot-age-review": ("older_than_days",),
    "sqs-lambda-polling-cost-review": ("max_mappings_per_region",),
    "tagging-missing-cost-tags": ("use_resource_groups_tagging_api",),
    "vpc-flow-log-attribution": (
        "max_log_groups_per_region",
        "max_query_polls",
        "poll_seconds",
        "query_limit",
        "query_timeout_seconds",
    ),
    "waf-cost-governance-review": ("association_detail_mode",),
}


__all__ = ["SCANNER_OPTION_NAMES", "get_known_scanner_option_names"]
