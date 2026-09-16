from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

NAT_GATEWAY_COST_REVIEW_EVIDENCE = (
    "NAT Gateway",
    "Cost Explorer usage type",
)

NAT_GATEWAY_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "nat-gateway-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "NAT Gateway cost review requires ec2:DescribeRegions to collect read-only NAT Gateway, Cost Explorer usage type evidence.",
                chargeable=False,
                evidence_categories=NAT_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeNatGateways",
                "required",
                "NAT Gateway cost review requires ec2:DescribeNatGateways to collect read-only NAT Gateway, Cost Explorer usage type evidence.",
                chargeable=False,
                evidence_categories=NAT_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeNatGateways is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "NAT Gateway cost review requires cloudwatch:GetMetricData to collect read-only throughput, packet, connection, and health evidence.",
                chargeable=False,
                evidence_categories=NAT_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="CloudWatch GetMetricData does not support resource-level IAM constraints.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "NAT Gateway cost review requires ce:GetCostAndUsage to collect read-only NAT Gateway, Cost Explorer usage type evidence.",
                chargeable=False,
                evidence_categories=NAT_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
