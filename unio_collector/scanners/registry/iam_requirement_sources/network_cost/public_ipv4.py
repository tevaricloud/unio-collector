from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

NETWORK_PUBLIC_IPV4_REVIEW_EVIDENCE = (
    "Public IPv4 address",
    "Elastic IP",
    "Network interface",
)

PUBLIC_IPV4_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "network-public-ipv4-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Public IPv4 cost review requires ec2:DescribeRegions to collect read-only Public IPv4 address, Elastic IP, Network interface evidence.",
                chargeable=False,
                evidence_categories=NETWORK_PUBLIC_IPV4_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeAddresses",
                "required",
                "Public IPv4 cost review requires ec2:DescribeAddresses to collect read-only Public IPv4 address, Elastic IP, Network interface evidence.",
                chargeable=False,
                evidence_categories=NETWORK_PUBLIC_IPV4_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeAddresses is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeNetworkInterfaces",
                "required",
                "Public IPv4 cost review requires ec2:DescribeNetworkInterfaces to collect read-only Public "
                "IPv4 address, Elastic IP, Network interface evidence.",
                chargeable=False,
                evidence_categories=NETWORK_PUBLIC_IPV4_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeNetworkInterfaces is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
