from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

NETWORK_PRIVATELINK_COST_REVIEW_EVIDENCE = (
    "VPC endpoint",
    "Interface endpoint",
    "Gateway Load Balancer endpoint",
    "VPC endpoint service",
)

PRIVATELINK_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "network-privatelink-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "PrivateLink cost review requires ec2:DescribeRegions to collect read-only VPC endpoint, Interface "
                "endpoint, Gateway Load Balancer endpoint, VPC endpoint service evidence.",
                chargeable=False,
                evidence_categories=NETWORK_PRIVATELINK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVpcEndpoints",
                "required",
                "PrivateLink cost review requires ec2:DescribeVpcEndpoints to collect read-only VPC endpoint, "
                "Interface endpoint, Gateway Load Balancer endpoint, VPC endpoint service evidence.",
                chargeable=False,
                evidence_categories=NETWORK_PRIVATELINK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVpcEndpoints is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVpcEndpointServiceConfigurations",
                "required",
                "PrivateLink cost review requires ec2:DescribeVpcEndpointServiceConfigurations "
                "to collect read-only VPC endpoint, Interface endpoint, Gateway Load Balancer "
                "endpoint, VPC endpoint service evidence.",
                chargeable=False,
                evidence_categories=NETWORK_PRIVATELINK_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVpcEndpointServiceConfigurations is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
