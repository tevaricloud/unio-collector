from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

SECRETS_MANAGER_COST_GOVERNANCE_REVIEW_EVIDENCE = ("Secrets Manager secret",)

SECRETS_MANAGER_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "secrets-manager-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Secrets Manager cost governance review requires ec2:DescribeRegions to collect read-only Secrets Manager secret evidence.",
                chargeable=False,
                evidence_categories=SECRETS_MANAGER_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "secretsmanager:ListSecrets",
                "required",
                "Secrets Manager cost governance review requires secretsmanager:ListSecrets to collect read-only Secrets Manager secret evidence.",
                chargeable=True,
                evidence_categories=SECRETS_MANAGER_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="secretsmanager:ListSecrets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Secrets Manager cost governance review requires ce:GetCostAndUsage to collect read-only Secrets Manager secret evidence.",
                chargeable=False,
                evidence_categories=SECRETS_MANAGER_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
