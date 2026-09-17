from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

TAGGING_MISSING_COST_TAGS_EVIDENCE = (
    "EC2 instance",
    "EBS volume",
    "Elastic IP",
    "NAT Gateway",
    "Auto Scaling group",
    "Load balancer",
)

TAGGING_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "tagging-missing-cost-tags": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Missing cost allocation tags requires ec2:DescribeRegions to collect read-only EC2 instance, EBS volume, "
                "Elastic IP, NAT Gateway, Auto Scaling group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeInstances",
                "required",
                "Missing cost allocation tags requires ec2:DescribeInstances to collect read-only EC2 instance, EBS "
                "volume, Elastic IP, NAT Gateway, Auto Scaling group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVolumes",
                "required",
                "Missing cost allocation tags requires ec2:DescribeVolumes to collect read-only EC2 instance, EBS volume, "
                "Elastic IP, NAT Gateway, Auto Scaling group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVolumes is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeAddresses",
                "required",
                "Missing cost allocation tags requires ec2:DescribeAddresses to collect read-only EC2 instance, EBS "
                "volume, Elastic IP, NAT Gateway, Auto Scaling group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeAddresses is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeNatGateways",
                "required",
                "Missing cost allocation tags requires ec2:DescribeNatGateways to collect read-only EC2 instance, EBS "
                "volume, Elastic IP, NAT Gateway, Auto Scaling group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeNatGateways is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeVpcs",
                "required",
                "Missing cost allocation tags requires ec2:DescribeVpcs to collect read-only EC2 instance, EBS volume, "
                "Elastic IP, NAT Gateway, Auto Scaling group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeVpcs is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeSubnets",
                "required",
                "Missing cost allocation tags requires ec2:DescribeSubnets to collect read-only EC2 instance, EBS volume, "
                "Elastic IP, NAT Gateway, Auto Scaling group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeSubnets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "autoscaling:DescribeAutoScalingGroups",
                "required",
                "Missing cost allocation tags requires autoscaling:DescribeAutoScalingGroups to collect "
                "read-only EC2 instance, EBS volume, Elastic IP, NAT Gateway, Auto Scaling group, Load "
                "balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="autoscaling:DescribeAutoScalingGroups is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeLoadBalancers",
                "required",
                "Missing cost allocation tags requires elasticloadbalancing:DescribeLoadBalancers "
                "to collect read-only EC2 instance, EBS volume, Elastic IP, NAT Gateway, Auto "
                "Scaling group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeLoadBalancers is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeTargetGroups",
                "required",
                "Missing cost allocation tags requires elasticloadbalancing:DescribeTargetGroups to "
                "collect read-only EC2 instance, EBS volume, Elastic IP, NAT Gateway, Auto Scaling "
                "group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeTargetGroups is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeTargetHealth",
                "required",
                "Missing cost allocation tags requires elasticloadbalancing:DescribeTargetHealth to "
                "collect read-only EC2 instance, EBS volume, Elastic IP, NAT Gateway, Auto Scaling "
                "group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeTargetHealth is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeTags",
                "required",
                "Missing cost allocation tags requires elasticloadbalancing:DescribeTags to collect "
                "read-only EC2 instance, EBS volume, Elastic IP, NAT Gateway, Auto Scaling group, Load "
                "balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeTags is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "tag:GetResources",
                "required",
                "Missing cost allocation tags requires tag:GetResources to collect read-only EC2 instance, EBS volume, "
                "Elastic IP, NAT Gateway, Auto Scaling group, Load balancer evidence.",
                chargeable=False,
                evidence_categories=TAGGING_MISSING_COST_TAGS_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="tag:GetResources is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
