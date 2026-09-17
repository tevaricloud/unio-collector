from __future__ import annotations  # noqa: D100

from unio_collector.scanners.scanner.definition import ScannerDefinition

SECURITY_GOVERNANCE_COVERAGE_SCANNERS: dict[str, ScannerDefinition] = {
    "aws-security-service-coverage-review": ScannerDefinition(
        scanner_id="aws-security-service-coverage-review",
        display_name="AWS security service coverage review",
        description=(
            "Reviews regional CloudTrail, AWS Config, GuardDuty, and Security "
            "Hub coverage as security governance evidence without using billing "
            "as the trigger or authority."
        ),
        aws_services=(
            "AWS CloudTrail",
            "AWS Config",
            "Amazon GuardDuty",
            "AWS Security Hub",
        ),
        resource_types=(
            "CloudTrail regional coverage",
            "AWS Config recorder",
            "GuardDuty detector",
            "Security Hub enabled standard",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "cloudtrail:DescribeTrails",
            "config:DescribeConfigurationRecorders",
            "config:DescribeConfigurationRecorderStatus",
            "config:DescribeConfigurationAggregators",
            "config:DescribeConformancePacks",
            "guardduty:ListDetectors",
            "securityhub:DescribeHub",
            "securityhub:GetEnabledStandards",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "cloudtrail:DescribeTrails",
            "config:DescribeConfigurationRecorders",
            "config:DescribeConfigurationRecorderStatus",
            "config:DescribeConfigurationAggregators",
            "config:DescribeConformancePacks",
            "guardduty:ListDetectors",
            "securityhub:DescribeHub",
            "securityhub:GetEnabledStandards",
        ),
        risk_level="medium",
        output_finding_types=(
            "cloudtrail_security_coverage_gap",
            "config_security_coverage_gap",
            "guardduty_security_coverage_gap",
            "securityhub_security_coverage_gap",
        ),
        maturity="experimental",
        limitations=(
            (
                "Does not decide whether a service should be enabled in every "
                "region; regional coverage must be validated against the approved "
                "security monitoring scope."
            ),
            "Does not inspect every Security Hub control result or GuardDuty finding.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized security service coverage evidence; summary side-channel writes are optional during strict replay."
        ),
    ),
    "aws-config-compliance-review": ScannerDefinition(
        scanner_id="aws-config-compliance-review",
        display_name="AWS Config compliance review",
        description=(
            "Collects AWS Config rule and conformance-pack compliance summaries "
            "as reusable governance evidence without treating Config as a full "
            "audit authority."
        ),
        aws_services=("AWS Config",),
        resource_types=(
            "AWS Config rule compliance",
            "AWS Config conformance pack compliance",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "config:DescribeComplianceByConfigRule",
            "config:DescribeConformancePacks",
            "config:DescribeConformancePackCompliance",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "config:DescribeComplianceByConfigRule",
            "config:DescribeConformancePacks",
            "config:DescribeConformancePackCompliance",
        ),
        risk_level="medium",
        output_finding_types=("aws_config_noncompliant_rule",),
        maturity="experimental",
        limitations=(
            "Only configured AWS Config rules and conformance packs can produce evidence; controls without rules remain outside this signal.",
            "Central aggregators or delegated administrator accounts may hold additional compliance context not visible to this scan role.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized AWS Config compliance evidence; summary side-channel writes are optional during strict replay."
        ),
    ),
    "securityhub-control-summary-review": ScannerDefinition(
        scanner_id="securityhub-control-summary-review",
        display_name="Security Hub control summary review",
        description=("Summarizes active failed Security Hub controls by region as governance evidence where Security Hub is already enabled."),
        aws_services=("AWS Security Hub",),
        resource_types=(
            "Security Hub control",
            "Security Hub active failed finding",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "securityhub:DescribeHub",
            "securityhub:GetFindings",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "securityhub:DescribeHub",
            "securityhub:GetFindings",
        ),
        risk_level="high",
        output_finding_types=("securityhub_failed_control",),
        maturity="experimental",
        limitations=(
            "Does not enable Security Hub and does not duplicate a full Security Hub or Prowler report.",
            "If Security Hub is delegated or disabled, the scanner records that state rather than failing the scan.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzer consumes serialized Security Hub control evidence; summary side-channel writes are optional during strict replay."),
    ),
    "cloudtrail-security-posture-review": ScannerDefinition(
        scanner_id="cloudtrail-security-posture-review",
        display_name="CloudTrail security posture review",
        description=(
            "Reviews visible CloudTrail trails for multi-region coverage, "
            "logging state, log file validation, and management-event capture "
            "as reusable audit logging evidence."
        ),
        aws_services=("AWS CloudTrail",),
        resource_types=(
            "CloudTrail trail",
            "CloudTrail security posture",
            "CloudTrail event selector",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
        ),
        risk_level="high",
        output_finding_types=(
            "cloudtrail_multi_region_security_gap",
            "cloudtrail_logging_disabled_gap",
            "cloudtrail_log_file_validation_gap",
            "cloudtrail_management_events_gap",
        ),
        maturity="experimental",
        limitations=(
            "Does not inspect CloudTrail Lake retention or data-event cost choices; those remain covered by audit cost governance evidence.",
            "Central organisation trails may be managed from another account, so security-owner validation is required before changing trails.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized CloudTrail security posture evidence "
            "with account identity carried in evidence; summary side-channel "
            "writes are optional during strict replay."
        ),
    ),
    "active-security-finding-review": ScannerDefinition(
        scanner_id="active-security-finding-review",
        display_name="Active security finding review",
        description=(
            "Collects active GuardDuty findings and, where Security Hub is "
            "enabled, active Security Hub findings as reusable security "
            "triage evidence for governance and readiness mapping."
        ),
        aws_services=("Amazon GuardDuty", "AWS Security Hub"),
        resource_types=(
            "GuardDuty finding",
            "Security Hub finding",
            "AWS security finding resource",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "guardduty:ListDetectors",
            "guardduty:ListFindings",
            "guardduty:GetFindings",
            "securityhub:GetFindings",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "guardduty:ListDetectors",
            "guardduty:ListFindings",
            "guardduty:GetFindings",
            "securityhub:GetFindings",
        ),
        risk_level="high",
        output_finding_types=(
            "guardduty_active_finding",
            "securityhub_active_finding",
        ),
        maturity="experimental",
        limitations=(
            "Does not decide whether a finding is a true positive; security owner triage remains required.",
            "Security Hub is optional and may be absent where it is not enabled or the account is not subscribed.",
            "Security Hub and GuardDuty coverage depends on regional service enablement and delegated-administrator design.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzer consumes serialized active security finding evidence and uses scanner metadata for deterministic finding ownership."
        ),
    ),
}

__all__ = ["SECURITY_GOVERNANCE_COVERAGE_SCANNERS"]
