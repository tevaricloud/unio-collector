from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

SECURITYHUB_INSPECTOR_MACIE_COST_REVIEW_EVIDENCE = (
    "Security standard",
    "Inspector account status",
    "Macie session",
    "Macie classification job",
)

SECURITYHUB_INSPECTOR_MACIE_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "securityhub-inspector-macie-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Security Hub, Inspector, and Macie cost governance review requires ec2:DescribeRegions to collect "
                "read-only Security standard, Inspector account status, Macie session, Macie classification job evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_INSPECTOR_MACIE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "securityhub:DescribeHub",
                "required",
                "Security Hub, Inspector, and Macie cost governance review requires securityhub:DescribeHub to "
                "collect read-only Security standard, Inspector account status, Macie session, Macie classification "
                "job evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_INSPECTOR_MACIE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="securityhub:DescribeHub is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "securityhub:GetEnabledStandards",
                "required",
                "Security Hub, Inspector, and Macie cost governance review requires "
                "securityhub:GetEnabledStandards to collect read-only Security standard, Inspector account "
                "status, Macie session, Macie classification job evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_INSPECTOR_MACIE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="securityhub:GetEnabledStandards is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "inspector2:BatchGetAccountStatus",
                "required",
                "Security Hub, Inspector, and Macie cost governance review requires "
                "inspector2:BatchGetAccountStatus to collect read-only Security standard, Inspector account "
                "status, Macie session, Macie classification job evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_INSPECTOR_MACIE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="inspector2:BatchGetAccountStatus is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "macie2:GetMacieSession",
                "required",
                "Security Hub, Inspector, and Macie cost governance review requires macie2:GetMacieSession to collect "
                "read-only Security standard, Inspector account status, Macie session, Macie classification job "
                "evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_INSPECTOR_MACIE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="macie2:GetMacieSession is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "macie2:ListClassificationJobs",
                "required",
                "Security Hub, Inspector, and Macie cost governance review requires "
                "macie2:ListClassificationJobs to collect read-only Security standard, Inspector account "
                "status, Macie session, Macie classification job evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_INSPECTOR_MACIE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="macie2:ListClassificationJobs is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Security Hub, Inspector, and Macie cost governance review requires ce:GetCostAndUsage to collect "
                "read-only Security standard, Inspector account status, Macie session, Macie classification job evidence.",
                chargeable=False,
                evidence_categories=SECURITYHUB_INSPECTOR_MACIE_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
