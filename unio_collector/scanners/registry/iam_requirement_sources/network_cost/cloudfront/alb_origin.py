from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE = (
    "CloudFront distribution",
    "CloudFront origin",
    "Application Load Balancer",
    "ALB listener",
    "EC2 security group",
    "WAF web ACL association",
    "ALB listener rule",
    "CloudFront VPC origin",
    "CloudFront managed prefix list",
)

CLOUDFRONT_ALB_ORIGIN_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "cloudfront-alb-origin-protection-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "cloudfront:ListDistributions",
                "required",
                "CloudFront ALB origin protection review requires cloudfront:ListDistributions to collect "
                "read-only CloudFront distribution, CloudFront origin, Application Load Balancer, ALB listener, "
                "EC2 security group, WAF web ACL association evidence.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudfront:ListDistributions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeLoadBalancers",
                "required",
                "CloudFront ALB origin protection review requires "
                "elasticloadbalancing:DescribeLoadBalancers to collect read-only CloudFront "
                "distribution, CloudFront origin, Application Load Balancer, ALB listener, EC2 "
                "security group, WAF web ACL association evidence.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeLoadBalancers is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeListeners",
                "required",
                "CloudFront ALB origin protection review requires "
                "elasticloadbalancing:DescribeListeners to collect read-only CloudFront distribution, "
                "CloudFront origin, Application Load Balancer, ALB listener, EC2 security group, WAF "
                "web ACL association evidence.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="elasticloadbalancing:DescribeListeners is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ec2:DescribeSecurityGroups",
                "required",
                "CloudFront ALB origin protection review requires ec2:DescribeSecurityGroups to collect read-only "
                "CloudFront distribution, CloudFront origin, Application Load Balancer, ALB listener, EC2 security "
                "group, WAF web ACL association evidence.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeSecurityGroups is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "wafv2:GetWebACLForResource",
                "required",
                "CloudFront ALB origin protection review requires wafv2:GetWebACLForResource to collect read-only "
                "CloudFront distribution, CloudFront origin, Application Load Balancer, ALB listener, EC2 security "
                "group, WAF web ACL association evidence.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="wafv2:GetWebACLForResource is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "elasticloadbalancing:DescribeRules",
                "required",
                "CloudFront ALB origin protection review requires read-only listener-rule conditions and actions.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="Listener rules are discovered from collected listener ARNs and the established scanner policy uses wildcard read scope.",
                conditional_on=None,
            ),
            Req(
                "cloudfront:GetOriginRequestPolicy",
                "conditional",
                "CloudFront ALB origin protection review uses origin request policies when cache behaviours reference them to determine Host forwarding.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE,
                resource_scope="resource_scoped_supported",
                resource_scope_reason="CloudFront origin request policies support resource-scoped read permissions.",
                conditional_on="a selected CloudFront cache behaviour references an origin request policy",
            ),
            Req(
                "cloudfront:GetVpcOrigin",
                "conditional",
                "CloudFront ALB origin protection review uses VPC-origin endpoint ARN and port evidence to correlate a referenced VPC origin to an ALB.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE,
                resource_scope="resource_scoped_supported",
                resource_scope_reason="CloudFront GetVpcOrigin supports the vpcorigin resource type.",
                conditional_on="a selected CloudFront origin contains VpcOriginConfig.VpcOriginId",
            ),
            Req(
                "ec2:DescribeManagedPrefixLists",
                "required",
                "CloudFront ALB origin protection review verifies CloudFront origin-facing managed prefix-list identity.",
                chargeable=False,
                evidence_categories=CLOUDFRONT_ALB_ORIGIN_PROTECTION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="EC2 managed prefix-list discovery is a read-only describe action rendered with wildcard scope.",
                conditional_on=None,
            ),
        ),
    ),
}
