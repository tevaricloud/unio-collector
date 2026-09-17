from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

NETWORK_TRANSIT_GATEWAY_COST_REVIEW_EVIDENCE = (
    "Transit Gateway",
    "Transit Gateway attachment",
    "Transit Gateway route table",
)

TRANSIT_GATEWAY_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "network-transit-gateway-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Transit Gateway cost review requires ec2:DescribeRegions to collect read-only Transit Gateway, Transit "
                "Gateway attachment, Transit Gateway route table evidence.",
                chargeable=False,
                evidence_categories=NETWORK_TRANSIT_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeTransitGateways",
                "required",
                "Transit Gateway cost review requires ec2:DescribeTransitGateways to collect read-only Transit "
                "Gateway, Transit Gateway attachment, Transit Gateway route table evidence.",
                chargeable=False,
                evidence_categories=NETWORK_TRANSIT_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeTransitGateways is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeTransitGatewayAttachments",
                "required",
                "Transit Gateway cost review requires ec2:DescribeTransitGatewayAttachments to collect "
                "read-only Transit Gateway, Transit Gateway attachment, Transit Gateway route table "
                "evidence.",
                chargeable=False,
                evidence_categories=NETWORK_TRANSIT_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeTransitGatewayAttachments is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeTransitGatewayRouteTables",
                "required",
                "Transit Gateway cost review requires ec2:DescribeTransitGatewayRouteTables to collect "
                "read-only Transit Gateway, Transit Gateway attachment, Transit Gateway route table "
                "evidence.",
                chargeable=False,
                evidence_categories=NETWORK_TRANSIT_GATEWAY_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeTransitGatewayRouteTables is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
