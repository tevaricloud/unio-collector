from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

WAF_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "Web ACL",
    "Managed rule group",
)

WAF_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "waf-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "WAF cost governance review requires ec2:DescribeRegions to collect read-only Web ACL, Managed rule group evidence.",
                chargeable=False,
                evidence_categories=WAF_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "wafv2:ListWebACLs",
                "required",
                "WAF cost governance review requires wafv2:ListWebACLs to collect read-only Web ACL, Managed rule group evidence.",
                chargeable=False,
                evidence_categories=WAF_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="wafv2:ListWebACLs is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "wafv2:GetWebACL",
                "required",
                "WAF cost governance review requires wafv2:GetWebACL to collect read-only Web ACL, Managed rule group evidence.",
                chargeable=False,
                evidence_categories=WAF_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="wafv2:GetWebACL is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "wafv2:ListResourcesForWebACL",
                "required",
                "WAF cost governance review requires wafv2:ListResourcesForWebACL to collect read-only Web ACL, Managed rule group evidence.",
                chargeable=False,
                evidence_categories=WAF_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="wafv2:ListResourcesForWebACL is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "WAF cost governance review requires ce:GetCostAndUsage to collect read-only Web ACL, Managed rule group evidence.",
                chargeable=False,
                evidence_categories=WAF_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
