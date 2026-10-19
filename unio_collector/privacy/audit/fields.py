"""Finite field inventories from Secrets Manager, CloudTrail and X-Ray DTOs."""

from __future__ import annotations

from unio_collector.privacy.s3.fields import Spec, fields

COMMON: dict[str, Spec] = {
    "": ("object", "safe_metadata", False),
    **fields("records regions", "array"),
    **fields("records[]", "object"),
    **fields("regions[] records[].region", "string", "region"),
    **fields("records[].account_id", "string", "aws_account_id"),
    **fields("records[].permission_errors", "array"),
    **fields("records[].permission_errors[]", "string", "free_text"),
}
BILLING: dict[str, Spec] = {
    **fields("records[].service_current_cost records[].service_previous_cost records[].regional_current_cost", "money", "cost", nullable=True),
    **fields("records[].service_cost_currency records[].regional_cost_currency", "string", "cost", nullable=True),
    **fields("records[].regional_cost_record_count", "count", "summary_count"),
    **fields("records[].derived_policy_fields_populated", "boolean"),
}
SECRETS: dict[str, Spec] = {
    **COMMON,
    **BILLING,
    **fields("analysis_reference_instant records[].raw_secrets[].last_accessed_at", "timestamp", "timestamp", nullable=True),
    **fields(
        (
            "records[].secret_count records[].active_secret_count records[].scheduled_deletion_secret_count "
            "records[].rotation_enabled_secret_count records[].rotation_disabled_secret_count "
            "records[].old_access_secret_count records[].missing_last_access_secret_count "
            "records[].replica_secret_count records[].custom_kms_key_secret_count "
            "records[].service_managed_secret_count records[].customer_managed_secret_count "
            "records[].rotation_lambda_secret_count records[].tagged_secret_count records[].untagged_secret_count"
        ),
        "count",
    ),
    **fields(
        (
            "records[].analysis_limitations records[].sample_secret_names records[].sample_kms_key_ids "
            "records[].sample_rotation_disabled_secret_names records[].sample_old_access_secret_names "
            "records[].sample_untagged_secret_names records[].sample_service_managed_secret_names "
            "records[].sample_replica_regions"
        ),
        "array",
    ),
    **fields("records[].analysis_limitations[]", "string", "free_text"),
    **fields(
        (
            "records[].sample_secret_names[] records[].sample_rotation_disabled_secret_names[] "
            "records[].sample_old_access_secret_names[] records[].sample_untagged_secret_names[] "
            "records[].sample_service_managed_secret_names[] records[].raw_secrets[].name"
        ),
        "string",
        "resource_name",
    ),
    **fields("records[].sample_kms_key_ids[]", "string", "arn_or_name"),
    **fields("records[].sample_replica_regions[] records[].raw_secrets[].replica_regions[]", "string", "region"),
    **fields("records[].raw_secrets", "array", nullable=True),
    **fields("records[].raw_secrets[]", "object"),
    **fields(
        ("records[].raw_secrets[].scheduled_deletion records[].raw_secrets[].rotation_enabled records[].raw_secrets[].rotation_lambda_configured"), "boolean"
    ),
    **fields("records[].raw_secrets[].replica_regions", "array"),
    **fields("records[].raw_secrets[].kms_key_id", "string", "arn_or_name", nullable=True),
    **fields("records[].raw_secrets[].owning_service", "string", "free_text", nullable=True),
    **fields("records[].raw_secrets[].tag_count", "count"),
    **fields("records[].raw_secrets[].tag_read_state", "tag_state"),
}
TRAIL_COST: dict[str, Spec] = {
    **COMMON,
    **BILLING,
    **fields(
        (
            "records[].trail_count records[].multi_region_trail_count records[].organization_trail_count "
            "records[].logging_trail_count records[].logging_stopped_trail_count "
            "records[].trail_status_error_count records[].trails_with_data_events "
            "records[].data_event_selector_count records[].advanced_event_selector_count "
            "records[].advanced_field_selector_count records[].data_resource_value_count "
            "records[].broad_data_resource_value_count records[].insight_selector_count "
            "records[].trails_with_insight_selectors records[].trails_with_management_events "
            "records[].logging_trails_with_management_events records[].event_data_store_count "
            "records[].event_data_store_long_retention_count records[].event_data_store_advanced_selector_count "
            "records[].log_file_validation_enabled_count records[].cloudwatch_logs_delivery_count "
            "records[].kms_encrypted_trail_count records[].s3_destination_count records[].sns_notification_count "
            "records[].management_event_selector_count"
        ),
        "count",
    ),
    **fields("records[].event_data_store_max_retention_days", "count", nullable=True),
    **fields(
        (
            "records[].data_resource_types records[].selector_read_write_types records[].advanced_selector_names "
            "records[].sample_data_resource_values records[].sample_event_data_store_names "
            "records[].event_data_store_statuses records[].sample_s3_bucket_names "
            "records[].sample_cloudwatch_log_group_arns records[].sample_kms_key_ids "
            "records[].sample_home_regions records[].sample_trail_names "
            "records[].sample_management_event_trail_names"
        ),
        "array",
    ),
    **fields("records[].data_resource_types[] records[].event_data_store_statuses[]", "string", "free_text"),
    **fields("records[].selector_read_write_types[]", "read_write"),
    **fields(
        (
            "records[].advanced_selector_names[] records[].sample_event_data_store_names[] "
            "records[].sample_trail_names[] records[].sample_management_event_trail_names[]"
        ),
        "string",
        "resource_name",
    ),
    **fields("records[].sample_data_resource_values[] records[].sample_cloudwatch_log_group_arns[] records[].sample_kms_key_ids[]", "string", "arn_or_name"),
    **fields("records[].sample_s3_bucket_names[]", "string", "bucket_name"),
    **fields("records[].sample_home_regions[]", "string", "region"),
    **fields("records[].raw_selectors records[].raw_event_data_stores", "array", nullable=True),
    **fields("records[].raw_event_data_stores[]", "object"),
    **fields("records[].raw_event_data_stores[].identifier", "string", "arn_or_name"),
    **fields("records[].raw_event_data_stores[].name", "string", "resource_name", nullable=True),
    **fields("records[].raw_event_data_stores[].status", "string", "free_text", nullable=True),
    **fields("records[].raw_event_data_stores[].retention_period_days", "count", nullable=True),
    **fields("records[].raw_event_data_stores[].advanced_selectors", "array"),
}
SELECTOR: dict[str, Spec] = {
    "": ("object", "safe_metadata", False),
    **fields("trail_name", "string", "resource_name"),
    **fields("selector_kind", "selector_kind"),
    **fields("selector_name", "string", "resource_name", nullable=True),
    **fields("read_write_type", "read_write", nullable=True),
    **fields("include_management_events", "boolean", nullable=True),
    **fields("exclude_management_event_sources resource_types resource_values event_categories field_conditions", "array"),
    **fields("exclude_management_event_sources[] resource_types[]", "string", "free_text"),
    **fields("event_categories[]", "event_category"),
    **fields("resource_values[]", "string", "arn_or_name"),
    **fields("field_conditions[]", "object"),
    **fields("field_conditions[].field", "string", "free_text"),
    **fields(
        (
            "field_conditions[].Equals field_conditions[].StartsWith field_conditions[].EndsWith "
            "field_conditions[].NotEquals field_conditions[].NotStartsWith field_conditions[].NotEndsWith"
        ),
        "array",
    ),
    **fields(
        (
            "field_conditions[].Equals[] field_conditions[].StartsWith[] field_conditions[].EndsWith[] "
            "field_conditions[].NotEquals[] field_conditions[].NotStartsWith[] field_conditions[].NotEndsWith[]"
        ),
        "string",
        "free_text",
    ),
}
for prefix in ("records[].raw_selectors[]", "records[].raw_event_data_stores[].advanced_selectors[]"):
    TRAIL_COST.update({prefix + ("." + path if path else ""): spec for path, spec in SELECTOR.items()})
TRAIL_SECURITY: dict[str, Spec] = {
    "": ("object", "safe_metadata", False),
    **fields("trails regions warnings", "array"),
    **fields("trails[]", "object"),
    **fields("account_id", "string", "aws_account_id"),
    **fields("trail_inventory_complete", "boolean"),
    **fields("regions[] trails[].region", "string", "region"),
    **fields("trails[].home_region", "string", "region", nullable=True),
    **fields("warnings[]", "string", "free_text"),
    **fields("trails[].name", "string", "resource_name"),
    **fields("trails[].arn", "string", "arn", nullable=True),
    **fields("trails[].s3_bucket_name", "string", "bucket_name", nullable=True),
    **fields("trails[].kms_key_id", "string", "arn_or_name", nullable=True),
    **fields(
        ("trails[].is_multi_region trails[].is_organization_trail trails[].log_file_validation_enabled trails[].is_logging trails[].management_events_enabled"),
        "boolean",
        nullable=True,
    ),
    **fields("trails[].read_write_type", "read_write_security", nullable=True),
}
XRAY: dict[str, Spec] = {
    **COMMON,
    **fields(
        (
            "records[].group_count records[].sampling_rule_count records[].custom_sampling_rule_count "
            "records[].sampling_statistics_count records[].sampled_trace_count records[].request_count "
            "records[].borrow_count"
        ),
        "count",
    ),
    **fields("records[].encryption_type", "encryption", nullable=True),
    **fields("records[].sample_group_names records[].sample_sampling_rule_names", "array"),
    **fields("records[].sample_group_names[] records[].sample_sampling_rule_names[]", "string", "resource_name"),
    **fields("cost_signal", "object"),
    **fields("cost_signal.service_name", "string", "free_text"),
    **fields("cost_signal.current_cost cost_signal.previous_cost cost_signal.absolute_delta", "money", "cost"),
    **fields("cost_signal.currency", "string", "cost"),
}
VOCABULARIES = {
    "event_category": {"Data", "Management", "NetworkActivity"},
    "tag_state": {"known_tagged", "known_untagged"},
    "selector_kind": {"basic", "advanced"},
    "read_write": {"All", "ReadOnly", "WriteOnly"},
    "read_write_security": {"All", "ReadOnly", "WriteOnly", "All, ReadOnly", "All, WriteOnly", "ReadOnly, WriteOnly", "All, ReadOnly, WriteOnly"},
    "encryption": {"NONE", "KMS"},
    "xray_service": {"AWS X-Ray", "AWS XRay", "Amazon X-Ray", "Amazon XRay"},
}
SCANNERS = {
    "secrets-manager-cost-governance-review": ("security_governance.secrets_manager.evidence", "SecretsManagerCostGovernanceEvidence", SECRETS),
    "cloudtrail-cost-governance-review": ("audit_cost.cloudtrail.cost.evidence", "CloudTrailCostGovernanceEvidence", TRAIL_COST),
    "cloudtrail-security-posture-review": ("audit_cost.cloudtrail.security.evidence", "CloudTrailSecurityPostureEvidence", TRAIL_SECURITY),
    "xray-tracing-cost-governance-review": ("xray.cost_evidence", "XRayCostGovernanceEvidence", XRAY),
}
