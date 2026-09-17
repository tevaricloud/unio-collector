from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

KMS_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "KMS key",
    "KMS alias",
)

KMS_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "kms-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "KMS cost governance review requires ec2:DescribeRegions to collect read-only KMS key, KMS alias evidence.",
                chargeable=False,
                evidence_categories=KMS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "kms:ListKeys",
                "required",
                "KMS cost governance review requires kms:ListKeys to collect read-only KMS key, KMS alias evidence.",
                chargeable=True,
                evidence_categories=KMS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="kms:ListKeys is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "kms:DescribeKey",
                "required",
                "KMS cost governance review requires kms:DescribeKey to collect read-only KMS key, KMS alias evidence.",
                chargeable=True,
                evidence_categories=KMS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="kms:DescribeKey is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "kms:GetKeyRotationStatus",
                "required",
                "KMS cost governance review requires kms:GetKeyRotationStatus to collect read-only KMS key, KMS alias evidence.",
                chargeable=True,
                evidence_categories=KMS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="kms:GetKeyRotationStatus is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "kms:ListAliases",
                "required",
                "KMS cost governance review requires kms:ListAliases to collect read-only KMS key, KMS alias evidence.",
                chargeable=True,
                evidence_categories=KMS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="kms:ListAliases is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "kms:ListResourceTags",
                "required",
                "KMS cost governance review requires kms:ListResourceTags to collect read-only KMS key, KMS alias evidence.",
                chargeable=True,
                evidence_categories=KMS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="kms:ListResourceTags is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "KMS cost governance review requires ce:GetCostAndUsage to collect read-only KMS key, KMS alias evidence.",
                chargeable=False,
                evidence_categories=KMS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
