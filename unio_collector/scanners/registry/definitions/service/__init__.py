from __future__ import annotations  # noqa: D104

from unio_collector.scanners.scanner.definition import ScannerDefinition

SERVICE_QUOTA_SCANNERS: dict[str, ScannerDefinition] = {
    "service-quota-proximity-review": ScannerDefinition(
        scanner_id="service-quota-proximity-review",
        display_name="Service Quotas proximity review",
        description=("Reviews a conservative set of countable regional Service Quotas against current resource counts and flags low remaining headroom."),
        aws_services=(
            "AWS Service Quotas",
            "Amazon EC2",
            "Amazon VPC",
            "Elastic Load Balancing",
        ),
        resource_types=(
            "Service quota",
            "Elastic IP address",
            "VPC",
            "Security group",
            "NAT gateway",
            "Application Load Balancer",
            "Network Load Balancer",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "servicequotas:ListServiceQuotas",
            "servicequotas:GetServiceQuota",
            "ec2:DescribeAddresses",
            "ec2:DescribeVpcs",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeNatGateways",
            "elasticloadbalancing:DescribeLoadBalancers",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "service-quotas:ListServiceQuotas",
            "service-quotas:GetServiceQuota",
            "ec2:DescribeAddresses",
            "ec2:DescribeVpcs",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeNatGateways",
            "elbv2:DescribeLoadBalancers",
        ),
        risk_level="medium",
        output_finding_types=("service_quota_proximity_review",),
        maturity="experimental",
        limitations=(
            "Checks a bounded first set of countable regional quotas only.",
            "Does not request quota increases or decide whether low headroom is acceptable for the workload.",
            "Service Quotas availability and quota names can vary by region and account.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzes serialized quota proximity payloads without AWS clients; "
            "account id, selected regions, warnings, and quota records are "
            "carried in the payload."
        ),
    ),
}
