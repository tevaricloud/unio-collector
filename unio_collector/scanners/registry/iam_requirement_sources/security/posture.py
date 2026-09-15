from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

ACTIVE_SECURITY_FINDING_REVIEW_EVIDENCE = (
    "GuardDuty finding",
    "Security Hub finding",
    "AWS security finding resource",
)

AWS_CONFIG_COMPLIANCE_REVIEW_EVIDENCE = (
    "AWS Config rule compliance",
    "AWS Config conformance pack compliance",
)

AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE = (
    "CloudTrail regional coverage",
    "AWS Config recorder",
    "GuardDuty detector",
    "Security Hub enabled standard",
)

CLOUDTRAIL_SECURITY_POSTURE_REVIEW_EVIDENCE = (
    "CloudTrail trail",
    "CloudTrail security posture",
    "CloudTrail event selector",
)

SECURITY_POSTURE_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "active-security-finding-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Active security finding review requires ec2:DescribeRegions to collect read-only GuardDuty finding, "
                "Security Hub finding, AWS security finding resource evidence.",
                chargeable=False,
                evidence_categories=ACTIVE_SECURITY_FINDING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "guardduty:ListDetectors",
                "required",
                "Active security finding review requires guardduty:ListDetectors to collect read-only GuardDuty "
                "finding, Security Hub finding, AWS security finding resource evidence.",
                chargeable=False,
                evidence_categories=ACTIVE_SECURITY_FINDING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="guardduty:ListDetectors is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "guardduty:ListFindings",
                "required",
                "Active security finding review requires guardduty:ListFindings to collect read-only GuardDuty "
                "finding, Security Hub finding, AWS security finding resource evidence.",
                chargeable=False,
                evidence_categories=ACTIVE_SECURITY_FINDING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="guardduty:ListFindings is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "guardduty:GetFindings",
                "required",
                "Active security finding review requires guardduty:GetFindings to collect read-only GuardDuty finding, "
                "Security Hub finding, AWS security finding resource evidence.",
                chargeable=False,
                evidence_categories=ACTIVE_SECURITY_FINDING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="guardduty:GetFindings is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "securityhub:GetFindings",
                "required",
                "Active security finding review requires securityhub:GetFindings to collect read-only GuardDuty "
                "finding, Security Hub finding, AWS security finding resource evidence.",
                chargeable=False,
                evidence_categories=ACTIVE_SECURITY_FINDING_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="securityhub:GetFindings is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "aws-config-compliance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "AWS Config compliance review requires ec2:DescribeRegions to collect read-only AWS Config rule "
                "compliance, AWS Config conformance pack compliance evidence.",
                chargeable=False,
                evidence_categories=AWS_CONFIG_COMPLIANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeComplianceByConfigRule",
                "required",
                "AWS Config compliance review requires config:DescribeComplianceByConfigRule to collect "
                "read-only AWS Config rule compliance, AWS Config conformance pack compliance evidence.",
                chargeable=False,
                evidence_categories=AWS_CONFIG_COMPLIANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeComplianceByConfigRule is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConformancePacks",
                "required",
                "AWS Config compliance review requires config:DescribeConformancePacks to collect read-only "
                "AWS Config rule compliance, AWS Config conformance pack compliance evidence.",
                chargeable=False,
                evidence_categories=AWS_CONFIG_COMPLIANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConformancePacks is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConformancePackCompliance",
                "required",
                "AWS Config compliance review requires config:DescribeConformancePackCompliance to "
                "collect read-only AWS Config rule compliance, AWS Config conformance pack "
                "compliance evidence.",
                chargeable=False,
                evidence_categories=AWS_CONFIG_COMPLIANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConformancePackCompliance is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "aws-security-service-coverage-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "AWS security service coverage review requires ec2:DescribeRegions to collect read-only CloudTrail "
                "regional coverage, AWS Config recorder, GuardDuty detector, Security Hub enabled standard evidence.",
                chargeable=False,
                evidence_categories=AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:DescribeTrails",
                "required",
                "AWS security service coverage review requires cloudtrail:DescribeTrails to collect read-only "
                "CloudTrail regional coverage, AWS Config recorder, GuardDuty detector, Security Hub enabled "
                "standard evidence.",
                chargeable=False,
                evidence_categories=AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:DescribeTrails is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConfigurationRecorders",
                "required",
                "AWS security service coverage review requires config:DescribeConfigurationRecorders to "
                "collect read-only CloudTrail regional coverage, AWS Config recorder, GuardDuty "
                "detector, Security Hub enabled standard evidence.",
                chargeable=False,
                evidence_categories=AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConfigurationRecorders is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConfigurationRecorderStatus",
                "required",
                "AWS security service coverage review requires "
                "config:DescribeConfigurationRecorderStatus to collect read-only CloudTrail "
                "regional coverage, AWS Config recorder, GuardDuty detector, Security Hub enabled "
                "standard evidence.",
                chargeable=False,
                evidence_categories=AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConfigurationRecorderStatus is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConfigurationAggregators",
                "required",
                "AWS security service coverage review requires "
                "config:DescribeConfigurationAggregators to collect read-only CloudTrail regional "
                "coverage, AWS Config recorder, GuardDuty detector, Security Hub enabled standard "
                "evidence.",
                chargeable=False,
                evidence_categories=AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConfigurationAggregators is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "config:DescribeConformancePacks",
                "required",
                "AWS security service coverage review requires config:DescribeConformancePacks to collect "
                "read-only CloudTrail regional coverage, AWS Config recorder, GuardDuty detector, Security "
                "Hub enabled standard evidence.",
                chargeable=False,
                evidence_categories=AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="config:DescribeConformancePacks is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "guardduty:ListDetectors",
                "required",
                "AWS security service coverage review requires guardduty:ListDetectors to collect read-only "
                "CloudTrail regional coverage, AWS Config recorder, GuardDuty detector, Security Hub enabled standard "
                "evidence.",
                chargeable=False,
                evidence_categories=AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="guardduty:ListDetectors is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "securityhub:DescribeHub",
                "required",
                "AWS security service coverage review requires securityhub:DescribeHub to collect read-only "
                "CloudTrail regional coverage, AWS Config recorder, GuardDuty detector, Security Hub enabled standard "
                "evidence.",
                chargeable=False,
                evidence_categories=AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="securityhub:DescribeHub is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "securityhub:GetEnabledStandards",
                "required",
                "AWS security service coverage review requires securityhub:GetEnabledStandards to collect "
                "read-only CloudTrail regional coverage, AWS Config recorder, GuardDuty detector, Security "
                "Hub enabled standard evidence.",
                chargeable=False,
                evidence_categories=AWS_SECURITY_SERVICE_COVERAGE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="securityhub:GetEnabledStandards is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "cloudtrail-security-posture-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "CloudTrail security posture review requires ec2:DescribeRegions to collect read-only CloudTrail trail, "
                "CloudTrail security posture, CloudTrail event selector evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_SECURITY_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:DescribeTrails",
                "required",
                "CloudTrail security posture review requires cloudtrail:DescribeTrails to collect read-only "
                "CloudTrail trail, CloudTrail security posture, CloudTrail event selector evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_SECURITY_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:DescribeTrails is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:GetTrailStatus",
                "required",
                "CloudTrail security posture review requires cloudtrail:GetTrailStatus to collect read-only "
                "CloudTrail trail, CloudTrail security posture, CloudTrail event selector evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_SECURITY_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:GetTrailStatus is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudtrail:GetEventSelectors",
                "required",
                "CloudTrail security posture review requires cloudtrail:GetEventSelectors to collect read-only "
                "CloudTrail trail, CloudTrail security posture, CloudTrail event selector evidence.",
                chargeable=False,
                evidence_categories=CLOUDTRAIL_SECURITY_POSTURE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudtrail:GetEventSelectors is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
