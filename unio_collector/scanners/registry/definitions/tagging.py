from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

TAGGING_SCANNERS: dict[str, ScannerDefinition] = {
    "tagging-missing-cost-tags": ScannerDefinition(
        scanner_id="tagging-missing-cost-tags",
        display_name="Missing cost allocation tags",
        description=(
            "Finds supported EC2-family resources with no tags, missing required cost tags, "
            "or associated resources that may need tag values copied or inferred from "
            "related tagged resources."
        ),
        aws_services=(
            "Amazon EC2",
            "Amazon Elastic Block Store",
            "Amazon VPC",
            "Amazon EC2 Auto Scaling",
            "Elastic Load Balancing",
            "Resource Groups Tagging API",
        ),
        resource_types=(
            "EC2 instance",
            "EBS volume",
            "Elastic IP",
            "NAT Gateway",
            "Auto Scaling group",
            "Load balancer",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "ec2:DescribeAddresses",
            "ec2:DescribeNatGateways",
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "autoscaling:DescribeAutoScalingGroups",
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeTargetGroups",
            "elasticloadbalancing:DescribeTargetHealth",
            "elasticloadbalancing:DescribeTags",
            "tag:GetResources",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "ec2:DescribeAddresses",
            "ec2:DescribeNatGateways",
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "autoscaling:DescribeAutoScalingGroups",
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeTargetGroups",
            "elasticloadbalancing:DescribeTargetHealth",
            "elasticloadbalancing:DescribeTags",
            "elbv2:DescribeLoadBalancers",
            "elbv2:DescribeTargetGroups",
            "elbv2:DescribeTargetHealth",
            "elbv2:DescribeTags",
            "resourcegroupstaggingapi:GetResources",
        ),
        risk_level="low",
        output_finding_types=(
            "resource_without_tags",
            "missing_required_cost_tags",
            "tag_propagation_candidate",
        ),
        maturity="experimental",
        limitations=(
            "Only checks supported EC2-family resources in this phase.",
            "Association-based tag candidates do not prove ownership.",
            "Naming-convention candidates require owner and deployment-source validation.",
            ("Resource Groups Tagging API is optional fast-path enrichment; direct EC2 inventory remains primary for untagged resources."),
            "Does not apply tags.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Carries taggable resource records, selected regions, and required "
            "cost tag keys in serialized evidence; graph export side effects "
            "are optional during offline analysis."
        ),
    ),
}

TAGGING_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "tagging",
    TAGGING_SCANNERS,
)
