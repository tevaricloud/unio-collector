from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

AUDIT_COST_SCANNERS: dict[str, ScannerDefinition] = {
    "cloudtrail-cost-governance-review": ScannerDefinition(
        scanner_id="cloudtrail-cost-governance-review",
        display_name="CloudTrail cost governance review",
        description=(
            "Reviews CloudTrail trail overlap, data event selectors, CloudTrail "
            "Lake event data stores, and insight selectors as audit-service cost "
            "governance signals, with cached Cost Explorer service and regional "
            "billing context where available."
        ),
        aws_services=("AWS CloudTrail", "AWS Cost Explorer"),
        resource_types=(
            "CloudTrail trail",
            "Event selector",
            "CloudTrail Lake event data store",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
            "cloudtrail:GetInsightSelectors",
            "cloudtrail:ListEventDataStores",
            "cloudtrail:GetEventDataStore",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
            "cloudtrail:GetInsightSelectors",
            "cloudtrail:ListEventDataStores",
            "cloudtrail:GetEventDataStore",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=(
            "cloudtrail_data_event_cost_review",
            "cloudtrail_insight_selector_cost_review",
            "cloudtrail_duplicate_management_event_review",
            "cloudtrail_lake_retention_cost_review",
        ),
        maturity="experimental",
        limitations=(
            "Does not recommend disabling CloudTrail or reducing audit coverage.",
            "Does not calculate exact event-volume cost without billing evidence.",
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual audit controls.",
            "Trail overlap requires compliance and security owner validation.",
            "CloudTrail Lake retention suitability requires audit-owner validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized CloudTrail cost governance evidence and uses scanner metadata only to stamp normalized evidence records."
        ),
    ),
    "config-cost-governance-review": ScannerDefinition(
        scanner_id="config-cost-governance-review",
        display_name="AWS Config cost governance review",
        description=(
            "Reviews AWS Config recorder status, recording scope, delivery channel "
            "destinations, rule source and trigger mix, and conformance-pack metadata "
            "as governance-service cost signals, with cached Cost Explorer service "
            "and regional billing context where available."
        ),
        aws_services=("AWS Config", "AWS Cost Explorer"),
        resource_types=(
            "Configuration recorder",
            "Config rule",
            "Conformance pack",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "config:DescribeConfigurationRecorders",
            "config:DescribeConfigurationRecorderStatus",
            "config:DescribeDeliveryChannels",
            "config:DescribeConfigRules",
            "config:DescribeConformancePacks",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "config:DescribeConfigurationRecorders",
            "config:DescribeConfigurationRecorderStatus",
            "config:DescribeDeliveryChannels",
            "config:DescribeConfigRules",
            "config:DescribeConformancePacks",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=(
            "config_recording_scope_cost_review",
            "config_rule_evaluation_cost_review",
        ),
        maturity="experimental",
        limitations=(
            "Does not recommend disabling AWS Config or compliance controls.",
            "Does not calculate exact rule evaluation cost without billing evidence.",
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual audit controls.",
            "Recording scope suitability requires compliance owner validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized Config cost governance evidence and uses scanner metadata only to stamp normalized evidence records."
        ),
    ),
    "guardduty-cost-governance-review": ScannerDefinition(
        scanner_id="guardduty-cost-governance-review",
        display_name="GuardDuty cost governance review",
        description=(
            "Reviews GuardDuty detectors and protection features as "
            "security-service cost governance signals, with cached Cost "
            "Explorer service and regional billing context where available."
        ),
        aws_services=("Amazon GuardDuty", "AWS Cost Explorer"),
        resource_types=("GuardDuty detector", "Protection feature"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "guardduty:ListDetectors",
            "guardduty:GetDetector",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "guardduty:ListDetectors",
            "guardduty:GetDetector",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("guardduty_protection_feature_cost_review",),
        maturity="experimental",
        limitations=(
            "Does not recommend disabling GuardDuty or protection features.",
            "Does not calculate exact GuardDuty feature cost without billing evidence.",
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual GuardDuty features.",
            "Feature suitability requires security owner validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized GuardDuty cost governance evidence and uses scanner metadata only to stamp normalized evidence records."
        ),
    ),
    "securityhub-inspector-macie-cost-review": ScannerDefinition(
        scanner_id="securityhub-inspector-macie-cost-review",
        display_name="Security Hub, Inspector, and Macie cost governance review",
        description=(
            "Reviews Security Hub standards, Inspector account status, Macie "
            "session status, and Macie classification jobs as security-service "
            "cost governance signals, with cached Cost Explorer service and "
            "regional billing context where available."
        ),
        aws_services=(
            "AWS Security Hub",
            "Amazon Inspector",
            "Amazon Macie",
            "AWS Cost Explorer",
        ),
        resource_types=(
            "Security standard",
            "Inspector account status",
            "Macie session",
            "Macie classification job",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "securityhub:DescribeHub",
            "securityhub:GetEnabledStandards",
            "inspector2:BatchGetAccountStatus",
            "macie2:GetMacieSession",
            "macie2:ListClassificationJobs",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "securityhub:DescribeHub",
            "securityhub:GetEnabledStandards",
            "inspector2:BatchGetAccountStatus",
            "macie2:GetMacieSession",
            "macie2:ListClassificationJobs",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("securityhub_inspector_macie_cost_review",),
        maturity="experimental",
        limitations=(
            "Does not recommend disabling Security Hub, Inspector, or Macie.",
            "Does not calculate exact security-service cost without billing evidence.",
            (
                "Cost Explorer context is service or region-level billing evidence "
                "and does not attribute cost to individual standards, scans, jobs, "
                "or service controls."
            ),
            "Coverage and scan scope suitability require security owner validation.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized Security Hub, Inspector, and Macie "
            "cost governance evidence and uses scanner metadata only to stamp "
            "normalized evidence records."
        ),
    ),
    "kms-cost-governance-review": ScannerDefinition(
        scanner_id="kms-cost-governance-review",
        display_name="KMS cost governance review",
        description=(
            "Reviews KMS key, alias, state, multi-Region, rotation, and tag "
            "metadata, including key spec, usage, origin, and multi-Region "
            "role, as security-cost governance signals."
        ),
        aws_services=("AWS KMS", "AWS Cost Explorer"),
        resource_types=("KMS key", "KMS alias"),
        default_enabled=False,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "kms:ListKeys",
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
            "kms:ListAliases",
            "kms:ListResourceTags",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "kms:ListKeys",
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
            "kms:ListAliases",
            "kms:ListResourceTags",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("kms_cost_governance_review",),
        maturity="experimental",
        limitations=(
            "AWS may charge for KMS API requests beyond applicable free tiers, so this scanner is chargeable-gated.",
            "Does not collect per-key request volume or per-key billing attribution.",
            "Does not inspect plaintext data or encrypted payload contents.",
            "Does not disable, rotate, delete, or schedule deletion for keys.",
            "Key lifecycle suitability requires security and application owner validation.",
        ),
        may_incur_charges=True,
        chargeable_reason=("Uses KMS List/Describe/Get APIs. AWS KMS request pricing can apply beyond included free tiers or account-specific allowances."),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized KMS cost governance evidence and uses scanner metadata only to stamp normalized evidence records."
        ),
    ),
    "secrets-manager-cost-governance-review": ScannerDefinition(
        scanner_id="secrets-manager-cost-governance-review",
        display_name="Secrets Manager cost governance review",
        description=(
            "Reviews Secrets Manager secret count, rotation, last-access "
            "metadata, replication, KMS key references, owning service, rotation "
            "Lambda, and tags as security-cost governance signals. Secret values "
            "are never read."
        ),
        aws_services=("AWS Secrets Manager", "AWS Cost Explorer"),
        resource_types=("Secrets Manager secret",),
        default_enabled=False,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "secretsmanager:ListSecrets",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "secretsmanager:ListSecrets",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("secrets_manager_cost_governance_review",),
        maturity="experimental",
        limitations=(
            "AWS may charge for Secrets Manager API calls, so this scanner is chargeable-gated.",
            "Does not retrieve secret values.",
            "Does not prove a secret is unused from last-access metadata alone.",
            "Does not delete, rotate, rename, or modify secrets.",
        ),
        may_incur_charges=True,
        chargeable_reason=(
            "Uses Secrets Manager ListSecrets. AWS Secrets Manager API request pricing can apply according to account usage and current AWS pricing."
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized Secrets Manager cost governance evidence and uses scanner metadata only to stamp normalized evidence records."
        ),
    ),
    "waf-cost-governance-review": ScannerDefinition(
        scanner_id="waf-cost-governance-review",
        display_name="WAF cost governance review",
        description=(
            "Reviews regional and CloudFront-scope WAF web ACLs, managed rule "
            "groups, rate-based rules, CAPTCHA or challenge actions, visibility "
            "settings, and visible associations as cost governance signals, with "
            "cached Cost Explorer service and regional billing context where "
            "available. association_detail_mode can be set to summary for "
            "faster development scans, but association-status findings require "
            "full mode."
        ),
        aws_services=("AWS WAF", "Amazon CloudFront", "AWS Cost Explorer"),
        resource_types=("Web ACL", "Managed rule group"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "wafv2:ListWebACLs",
            "wafv2:GetWebACL",
            "wafv2:ListResourcesForWebACL",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "wafv2:ListWebACLs",
            "wafv2:GetWebACL",
            "wafv2:ListResourcesForWebACL",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=(
            "waf_managed_rule_cost_review",
            "waf_unassociated_acl_cost_review",
        ),
        maturity="experimental",
        limitations=(
            "Does not recommend disabling WAF or managed protections.",
            "Does not calculate request-based WAF cost without billing or metric evidence.",
            "Cost Explorer context is service or region-level billing evidence and does not attribute cost to individual audit controls.",
            "Some CloudFront or regional associations may be unavailable due to permissions.",
            "association_detail_mode=summary skips ListResourcesForWebACL and suppresses WAF association-status findings.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized WAF cost governance evidence and uses scanner metadata only to stamp normalized evidence records."
        ),
    ),
}

AUDIT_COST_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "audit_cost",
    AUDIT_COST_SCANNERS,
)
