from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

GUARDDUTY_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "GuardDuty detector",
    "Protection feature",
)

GUARDDUTY_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "guardduty-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "GuardDuty cost governance review requires ec2:DescribeRegions to collect read-only GuardDuty detector, Protection feature evidence.",
                chargeable=False,
                evidence_categories=GUARDDUTY_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "guardduty:ListDetectors",
                "required",
                "GuardDuty cost governance review requires guardduty:ListDetectors to collect read-only GuardDuty detector, Protection feature evidence.",
                chargeable=False,
                evidence_categories=GUARDDUTY_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="guardduty:ListDetectors is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "guardduty:GetDetector",
                "required",
                "GuardDuty cost governance review requires guardduty:GetDetector to collect read-only GuardDuty detector, Protection feature evidence.",
                chargeable=False,
                evidence_categories=GUARDDUTY_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="guardduty:GetDetector is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "GuardDuty cost governance review requires ce:GetCostAndUsage to collect read-only GuardDuty detector, Protection feature evidence.",
                chargeable=False,
                evidence_categories=GUARDDUTY_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
