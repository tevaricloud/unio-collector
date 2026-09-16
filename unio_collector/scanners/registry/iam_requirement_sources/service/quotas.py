from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

SERVICE_QUOTA_PROXIMITY_REVIEW_EVIDENCE = (
    "Service quota",
    "Elastic IP address",
    "VPC",
    "Security group",
    "NAT gateway",
    "Application Load Balancer",
    "Network Load Balancer",
)

SERVICE_QUOTAS_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "service-quota-proximity-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Service Quotas proximity review requires ec2:DescribeRegions to collect read-only Service quota, Elastic "
                "IP address, VPC, Security group, NAT gateway, Application Load Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=SERVICE_QUOTA_PROXIMITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "servicequotas:ListServiceQuotas",
                "required",
                "Service Quotas proximity review requires servicequotas:ListServiceQuotas to collect "
                "read-only Service quota, Elastic IP address, VPC, Security group, NAT gateway, Application "
                "Load Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=SERVICE_QUOTA_PROXIMITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="servicequotas:ListServiceQuotas is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "servicequotas:GetServiceQuota",
                "required",
                "Service Quotas proximity review requires servicequotas:GetServiceQuota to collect read-only "
                "Service quota, Elastic IP address, VPC, Security group, NAT gateway, Application Load "
                "Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=SERVICE_QUOTA_PROXIMITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="servicequotas:GetServiceQuota is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeAddresses",
                "required",
                "Service Quotas proximity review requires ec2:DescribeAddresses to collect read-only Service quota, "
                "Elastic IP address, VPC, Security group, NAT gateway, Application Load Balancer, Network Load Balancer "
                "evidence.",
                chargeable=False,
                evidence_categories=SERVICE_QUOTA_PROXIMITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeAddresses is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVpcs",
                "required",
                "Service Quotas proximity review requires ec2:DescribeVpcs to collect read-only Service quota, Elastic IP "
                "address, VPC, Security group, NAT gateway, Application Load Balancer, Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=SERVICE_QUOTA_PROXIMITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVpcs is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeSecurityGroups",
                "required",
                "Service Quotas proximity review requires ec2:DescribeSecurityGroups to collect read-only Service "
                "quota, Elastic IP address, VPC, Security group, NAT gateway, Application Load Balancer, Network "
                "Load Balancer evidence.",
                chargeable=False,
                evidence_categories=SERVICE_QUOTA_PROXIMITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeSecurityGroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeNatGateways",
                "required",
                "Service Quotas proximity review requires ec2:DescribeNatGateways to collect read-only Service quota, "
                "Elastic IP address, VPC, Security group, NAT gateway, Application Load Balancer, Network Load "
                "Balancer evidence.",
                chargeable=False,
                evidence_categories=SERVICE_QUOTA_PROXIMITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeNatGateways is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeLoadBalancers",
                "required",
                "Service Quotas proximity review requires "
                "elasticloadbalancing:DescribeLoadBalancers to collect read-only Service quota, "
                "Elastic IP address, VPC, Security group, NAT gateway, Application Load Balancer, "
                "Network Load Balancer evidence.",
                chargeable=False,
                evidence_categories=SERVICE_QUOTA_PROXIMITY_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeLoadBalancers is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
