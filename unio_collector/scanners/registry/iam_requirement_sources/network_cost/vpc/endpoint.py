from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

NETWORK_VPC_ENDPOINT_OPPORTUNITY_REVIEW_EVIDENCE = (
    "VPC",
    "Route table",
    "NAT Gateway",
    "VPC endpoint",
)

VPC_ENDPOINT_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "network-vpc-endpoint-opportunity-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "VPC endpoint opportunity review requires ec2:DescribeRegions to collect read-only VPC, Route table, NAT Gateway, VPC endpoint evidence.",
                chargeable=False,
                evidence_categories=NETWORK_VPC_ENDPOINT_OPPORTUNITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVpcs",
                "required",
                "VPC endpoint opportunity review requires ec2:DescribeVpcs to collect read-only VPC tag evidence.",
                chargeable=False,
                evidence_categories=NETWORK_VPC_ENDPOINT_OPPORTUNITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVpcs requires wildcard discovery for selected regions.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeRouteTables",
                "required",
                "VPC endpoint opportunity review requires ec2:DescribeRouteTables to collect read-only VPC, Route table, NAT Gateway, VPC endpoint evidence.",
                chargeable=False,
                evidence_categories=NETWORK_VPC_ENDPOINT_OPPORTUNITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRouteTables is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVpcEndpoints",
                "required",
                "VPC endpoint opportunity review requires ec2:DescribeVpcEndpoints to collect read-only VPC, Route table, NAT Gateway, VPC endpoint evidence.",
                chargeable=False,
                evidence_categories=NETWORK_VPC_ENDPOINT_OPPORTUNITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVpcEndpoints is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeNatGateways",
                "required",
                "VPC endpoint opportunity review requires ec2:DescribeNatGateways to collect read-only VPC, Route table, NAT Gateway, VPC endpoint evidence.",
                chargeable=False,
                evidence_categories=NETWORK_VPC_ENDPOINT_OPPORTUNITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeNatGateways is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeNetworkInterfaces",
                "required",
                "VPC endpoint opportunity review requires ec2:DescribeNetworkInterfaces to collect read-only "
                "VPC, Route table, NAT Gateway, VPC endpoint evidence.",
                chargeable=False,
                evidence_categories=NETWORK_VPC_ENDPOINT_OPPORTUNITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeNetworkInterfaces is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeSubnets",
                "required",
                "VPC endpoint opportunity review requires ec2:DescribeSubnets to collect read-only VPC, Route table, NAT Gateway, VPC endpoint evidence.",
                chargeable=False,
                evidence_categories=NETWORK_VPC_ENDPOINT_OPPORTUNITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeSubnets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
