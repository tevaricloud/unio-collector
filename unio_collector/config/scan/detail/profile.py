from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.config.scan.detail.contract import ScanDetailOptionContract
from unio_collector.scanners.scanner.option_override import ScannerOptionOverride

FULL_SCAN_DETAIL_PROFILE = "full"
DEVELOPMENT_SCAN_DETAIL_PROFILE = "development"
SCAN_DETAIL_PROFILE_IDS = (
    FULL_SCAN_DETAIL_PROFILE,
    DEVELOPMENT_SCAN_DETAIL_PROFILE,
)

_FULL_OR_SUMMARY = frozenset({"full", "summary"})
_FULL_OR_BILLING_ACTIVE = frozenset({"full", "billing-active"})
_FULL_OR_PRIORITIZED = frozenset({"full", "prioritized"})


@dataclass(frozen=True)
class ScanDetailProfile:  # noqa: D101
    profile_id: str
    description: str
    scanner_option_overrides: tuple[ScannerOptionOverride, ...] = ()
    scanner_option_defaults: tuple[ScannerOptionOverride, ...] = ()


def _option(
    scanner_id: str,
    option_name: str,
    development_value: object,
    full_value: object,
    *,
    full_value_is_authoritative: bool = True,
    full_value_requires_explicit_selection: bool = False,
    allowed_values: frozenset[object] | None = None,
) -> ScanDetailOptionContract:
    return ScanDetailOptionContract(
        scanner_id=scanner_id,
        option_name=option_name,
        development_value=development_value,
        full_value=full_value,
        full_value_is_authoritative=full_value_is_authoritative,
        full_value_requires_explicit_selection=(full_value_requires_explicit_selection),
        allowed_values=allowed_values,
    )


SCAN_DETAIL_OPTION_CONTRACTS = (
    _option("dynamodb-cost-governance-review", "retention_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("dynamodb-cost-governance-review", "metric_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("dynamodb-cost-governance-review", "autoscaling_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("dynamodb-cost-governance-review", "table_detail_regional_mode", "billing-active", "full", allowed_values=_FULL_OR_BILLING_ACTIVE),
    _option("billing-alerts-and-budgets-review", "subscriber_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("billing-alerts-and-budgets-review", "monitor_detail_mode", "budgets-only", "full", allowed_values=frozenset({"budgets-only", "full"})),
    _option("backup-retention-review", "selection_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option(
        "backup-retention-review",
        "collect_tags",
        development_value=False,
        full_value=True,
    ),
    _option(
        "lambda-cost-cycle-risk-review",
        "collect_tags",
        development_value=False,
        full_value=True,
    ),
    _option("lambda-cost-cycle-risk-review", "s3_notification_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option(
        "lambda-cost-cycle-risk-review",
        "s3_policy_scan_max_functions",
        50,
        0,
        full_value_requires_explicit_selection=True,
    ),
    _option(
        "lambda-cost-cycle-risk-review",
        "max_s3_buckets",
        25,
        None,
        full_value_requires_explicit_selection=True,
    ),
    _option("ec2-idle-instance-review", "max_instances_per_region", 25, 0),
    _option(
        "iam-account-security-review",
        "policy_detail_mode",
        "administrator-access-only",
        "full",
        allowed_values=frozenset(
            {"administrator-access-only", "full", "off"},
        ),
    ),
    _option("sqs-lambda-polling-cost-review", "max_mappings_per_region", 25, 0),
    _option("api-gateway-cost-review", "vpc_link_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("ecs-cost-governance-review", "task_definition_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("ecs-cost-governance-review", "regional_collection_mode", "billing-active", "full", allowed_values=_FULL_OR_BILLING_ACTIVE),
    _option("elasticache-cost-review", "metric_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("waf-cost-governance-review", "association_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("config-cost-governance-review", "rule_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("load-balancer-idle-review", "target_health_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option(
        "load-balancer-idle-review",
        "collect_tags",
        development_value=False,
        full_value=True,
    ),
    _option("cloudwatch-idle-log-review", "metric_detail_mode", "prioritized", "full", allowed_values=_FULL_OR_PRIORITIZED),
    _option(
        "cloudwatch-idle-log-review",
        "max_metric_log_groups_per_region",
        50,
        0,
        full_value_is_authoritative=False,
    ),
    _option(
        "cloudwatch-idle-log-review",
        "metric_prioritization_scope",
        "global",
        "regional",
        full_value_is_authoritative=False,
        allowed_values=frozenset({"global", "regional"}),
    ),
    _option(
        "cloudwatch-idle-log-review",
        "max_metric_log_groups",
        50,
        0,
        full_value_is_authoritative=False,
    ),
    _option("cloudwatch-log-cost-and-relevance-review", "metric_detail_mode", "prioritized", "full", allowed_values=_FULL_OR_PRIORITIZED),
    _option(
        "cloudwatch-log-cost-and-relevance-review",
        "max_metric_log_groups_per_region",
        50,
        0,
        full_value_is_authoritative=False,
    ),
    _option(
        "cloudwatch-log-cost-and-relevance-review",
        "metric_prioritization_scope",
        "global",
        "regional",
        full_value_is_authoritative=False,
        allowed_values=frozenset({"global", "regional"}),
    ),
    _option(
        "cloudwatch-log-cost-and-relevance-review",
        "max_metric_log_groups",
        50,
        0,
        full_value_is_authoritative=False,
    ),
    _option("cloudfront-origin-cost-review", "invalidation_detail_mode", "summary", "full", allowed_values=_FULL_OR_SUMMARY),
    _option("s3-lifecycle-cost-review", "collection_profile", "fast-dev", "full", allowed_values=frozenset({"fast-dev", "full", "standard"})),
    _option("s3-lifecycle-cost-review", "lifecycle_detail_mode", "prioritized", "full", allowed_values=_FULL_OR_PRIORITIZED),
    _option(
        "s3-lifecycle-cost-review",
        "prioritized_lifecycle_bucket_count",
        25,
        25,
        full_value_is_authoritative=False,
    ),
    _option(
        "s3-lifecycle-cost-review",
        "include_lifecycle_metric_unknown_buckets",
        development_value=False,
        full_value=True,
    ),
    _option("s3-versioning-and-replication-review", "collection_profile", "fast-dev", "full", allowed_values=frozenset({"fast-dev", "full", "standard"})),
    _option("s3-versioning-and-replication-review", "lifecycle_detail_mode", "prioritized", "full", allowed_values=_FULL_OR_PRIORITIZED),
    _option(
        "s3-versioning-and-replication-review",
        "prioritized_lifecycle_bucket_count",
        25,
        25,
        full_value_is_authoritative=False,
    ),
    _option(
        "s3-versioning-and-replication-review",
        "include_lifecycle_metric_unknown_buckets",
        development_value=False,
        full_value=True,
    ),
    _option("s3-incomplete-multipart-review", "max_multipart_buckets", 15, 0),
    _option(
        "s3-incomplete-multipart-review",
        "multipart_bucket_selection_mode",
        "storage-prioritized",
        "inventory-order",
        allowed_values=frozenset({"inventory-order", "storage-prioritized"}),
    ),
)


DEVELOPMENT_PERFORMANCE_DEFAULTS = (
    ScannerOptionOverride("s3-lifecycle-cost-review", "max_bucket_workers", 32),
    ScannerOptionOverride("s3-versioning-and-replication-review", "max_bucket_workers", 32),
    ScannerOptionOverride("s3-incomplete-multipart-review", "max_bucket_workers", 32),
)


def _profile_overrides(profile_id: str) -> tuple[ScannerOptionOverride, ...]:
    return tuple(
        contract.build_override(
            contract.full_value if profile_id == FULL_SCAN_DETAIL_PROFILE else contract.development_value,
        )
        for contract in SCAN_DETAIL_OPTION_CONTRACTS
        if profile_id != FULL_SCAN_DETAIL_PROFILE or contract.full_value_is_authoritative
    )


SCAN_DETAIL_PROFILES: dict[str, ScanDetailProfile] = {
    FULL_SCAN_DETAIL_PROFILE: ScanDetailProfile(
        profile_id=FULL_SCAN_DETAIL_PROFILE,
        description="Accuracy-first scanner detail. No scanner detail is reduced.",
        scanner_option_overrides=_profile_overrides(FULL_SCAN_DETAIL_PROFILE),
    ),
    DEVELOPMENT_SCAN_DETAIL_PROFILE: ScanDetailProfile(
        profile_id=DEVELOPMENT_SCAN_DETAIL_PROFILE,
        description=(
            "Faster development detail. Scanner-level summary modes reduce expensive per-resource metadata checks while recording coverage limitations."
        ),
        scanner_option_overrides=_profile_overrides(
            DEVELOPMENT_SCAN_DETAIL_PROFILE,
        ),
        scanner_option_defaults=DEVELOPMENT_PERFORMANCE_DEFAULTS,
    ),
}
