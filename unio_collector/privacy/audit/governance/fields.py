"""Explicit field/type contracts from the four governance producer DTOs."""

from __future__ import annotations

from unio_collector.privacy.audit.fields import BILLING, COMMON
from unio_collector.privacy.s3.fields import Spec, fields

FINANCIAL = {path: spec for path, spec in BILLING.items() if path != "records[].derived_policy_fields_populated"}
VOCABULARIES = {
    "recording_strategy": {"ALL_SUPPORTED_RESOURCE_TYPES", "INCLUSION_BY_RESOURCE_TYPES", "EXCLUSION_BY_RESOURCE_TYPES"},
    "recording_frequency": {"CONTINUOUS", "DAILY"},
    "delivery_frequency": {"One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"},
    "recorder_status": {"Pending", "Success", "Failure", "NotApplicable"},
    "detector_status": {"ENABLED", "DISABLED"},
    "publishing_frequency": {"FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"},
    "standard_status": {"PENDING", "READY", "FAILED", "DELETING", "INCOMPLETE"},
    "inspector_status": {"ENABLING", "ENABLED", "DISABLING", "DISABLED", "SUSPENDING", "SUSPENDED"},
    "macie_status": {"ENABLED", "PAUSED"},
    "job_status": {"RUNNING", "PAUSED", "CANCELLED", "COMPLETE", "IDLE", "USER_PAUSED"},
    "association_service": {"elasticloadbalancing", "apigateway", "appsync", "cognito-idp", "apprunner", "ec2", "amplify", "bedrock-agentcore"},
    "waf_scope": {"REGIONAL", "CLOUDFRONT"},
    "association_mode": {"full", "summary"},
    "association_skip": {"skipped_by_association_detail_mode"},
    "waf_action": {"ALLOW", "BLOCK", "COUNT", "CAPTCHA", "CHALLENGE", "NONE"},
}


def record_fields(names: str, kind: str, category: str = "safe_metadata", *, nullable: bool = False) -> dict[str, Spec]:
    """Expand a finite reviewed list, never observed provider keys."""
    return fields(" ".join("records[]." + name for name in names.split()), kind, category, nullable=nullable)


CONFIG = {
    **COMMON,
    **FINANCIAL,
    **record_fields(
        (
            "recorder_count recording_enabled_count recording_stopped_count delivery_channel_count delivery_s3_bucket_count "
            "delivery_sns_topic_count all_supported_recording_count include_global_resource_types_count config_rule_count "
            "aws_managed_rule_count custom_rule_count periodic_rule_count change_triggered_rule_count conformance_pack_count "
            "targeted_resource_type_count excluded_resource_type_count continuous_recording_count daily_recording_count "
            "recorder_last_error_count"
        ),
        "count",
        "summary_count",
    ),
    **record_fields(
        (
            "recording_strategy_types recording_frequency_values delivery_frequency_values recorder_last_status_values "
            "sample_recorded_resource_types sample_excluded_resource_types sample_recorder_names sample_delivery_channel_names "
            "sample_rule_names sample_conformance_pack_names"
        ),
        "array",
    ),
    **record_fields("recording_strategy_types[]", "recording_strategy"),
    **record_fields("recording_frequency_values[]", "recording_frequency"),
    **record_fields("delivery_frequency_values[]", "delivery_frequency"),
    **record_fields("recorder_last_status_values[]", "recorder_status"),
    **record_fields("sample_recorded_resource_types[] sample_excluded_resource_types[]", "string", "free_text"),
    **record_fields("sample_recorder_names[] sample_delivery_channel_names[] sample_rule_names[] sample_conformance_pack_names[]", "string", "resource_name"),
}
GUARDDUTY = {
    **COMMON,
    **FINANCIAL,
    **record_fields("detector_count enabled_detector_count enabled_feature_count disabled_feature_count", "count", "summary_count"),
    **record_fields("feature_status_counts", "object"),
    **record_fields("feature_status_counts.ENABLED feature_status_counts.DISABLED feature_status_counts.UNKNOWN", "count", "summary_count"),
    **record_fields("finding_publishing_frequencies detector_status_values enabled_feature_names sample_disabled_feature_names sample_detector_ids", "array"),
    **record_fields("finding_publishing_frequencies[]", "publishing_frequency"),
    **record_fields("detector_status_values[]", "detector_status"),
    **record_fields("enabled_feature_names[] sample_disabled_feature_names[]", "string", "free_text"),
    **record_fields("sample_detector_ids[]", "string", "resource_id"),
}
SECURITY = {
    **COMMON,
    **BILLING,
    **record_fields("securityhub_enabled inspector_enabled macie_enabled", "boolean"),
    **record_fields(
        (
            "securityhub_standard_count securityhub_ready_standard_count securityhub_non_ready_standard_count "
            "macie_classification_job_count macie_active_or_scheduled_job_count"
        ),
        "count",
        "summary_count",
    ),
    **record_fields(
        "securityhub_standard_statuses sample_securityhub_standard_arns inspector_resource_statuses macie_job_statuses sample_macie_job_ids", "array"
    ),
    **record_fields("securityhub_standard_statuses[]", "standard_status"),
    **record_fields("sample_securityhub_standard_arns[]", "string", "arn"),
    **record_fields("inspector_status", "inspector_status", nullable=True),
    **record_fields("inspector_resource_statuses[]", "inspector_status"),
    **record_fields("macie_status", "macie_status", nullable=True),
    **record_fields("macie_finding_publishing_frequency", "publishing_frequency", nullable=True),
    **record_fields("macie_job_statuses[]", "job_status"),
    **record_fields("sample_macie_job_ids[]", "string", "resource_id"),
    **record_fields("macie_job_status_counts", "object", nullable=True),
    **record_fields(" ".join("macie_job_status_counts." + key for key in sorted(VOCABULARIES["job_status"])), "count", "summary_count"),
}
WAF = {
    **COMMON,
    **FINANCIAL,
    **record_fields("scope", "waf_scope"),
    **record_fields(
        (
            "web_acl_count web_acl_capacity_total managed_rule_group_count rate_based_rule_count captcha_rule_count "
            "challenge_rule_count count_action_rule_count allow_action_rule_count block_action_rule_count "
            "default_allow_acl_count default_block_acl_count rule_count cloudwatch_metrics_enabled_count "
            "sampled_requests_enabled_count associated_resource_count"
        ),
        "count",
        "summary_count",
    ),
    **record_fields("association_detail_mode", "association_mode"),
    **record_fields("association_metadata_collected", "boolean"),
    **record_fields("association_skip_reason", "association_skip", nullable=True),
    **record_fields("associated_resource_types rule_action_types managed_rule_group_names sample_web_acl_names sample_rate_limits", "array"),
    **record_fields("associated_resource_types[]", "association_service"),
    **record_fields("rule_action_types[]", "waf_action"),
    **record_fields("managed_rule_group_names[] sample_web_acl_names[]", "string", "resource_name"),
    **record_fields("sample_rate_limits[]", "count", "summary_count"),
}
SCANNERS = {
    "config-cost-governance-review": ("config.cost_governance.evidence", "ConfigCostGovernanceEvidence", CONFIG),
    "guardduty-cost-governance-review": ("security_governance.guardduty.evidence", "GuardDutyCostGovernanceEvidence", GUARDDUTY),
    "securityhub-inspector-macie-cost-review": (
        "security_governance.securityhub_inspector_macie.evidence",
        "SecurityHubInspectorMacieCostGovernanceEvidence",
        SECURITY,
    ),
    "waf-cost-governance-review": ("security_governance.waf.evidence", "WafCostGovernanceEvidence", WAF),
}
