from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

DYNAMODB_SCANNERS: dict[str, ScannerDefinition] = {
    "dynamodb-cost-governance-review": ScannerDefinition(
        scanner_id="dynamodb-cost-governance-review",
        display_name="DynamoDB cost governance review",
        description=(
            "Reviews DynamoDB table billing mode, provisioned capacity, global "
            "secondary indexes, point-in-time recovery, TTL, streams, table class, "
            "tagging, Application Auto Scaling coverage, CloudWatch metrics, and "
            "Cost Explorer context as data-store cost governance signals."
        ),
        aws_services=(
            "Amazon DynamoDB",
            "Application Auto Scaling",
            "Amazon CloudWatch",
            "AWS Cost Explorer",
            "AWS Resource Groups Tagging API",
        ),
        resource_types=(
            "DynamoDB table",
            "DynamoDB global secondary index",
            "Application Auto Scaling target",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "dynamodb:ListTables",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:ListTagsOfResource",
            "tag:GetResources",
            "application-autoscaling:DescribeScalableTargets",
            "application-autoscaling:DescribeScalingPolicies",
            "cloudwatch:GetMetricData",
            "ce:GetCostAndUsage",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "dynamodb:ListTables",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:ListTagsOfResource",
            "resourcegroupstaggingapi:GetResources",
            "application-autoscaling:DescribeScalableTargets",
            "application-autoscaling:DescribeScalingPolicies",
            "cloudwatch:GetMetricData",
            "ce:GetCostAndUsage",
        ),
        risk_level="medium",
        output_finding_types=("dynamodb_cost_governance_review",),
        maturity="experimental",
        limitations=(
            "Does not read DynamoDB table items or execute queries.",
            (
                "Collects CloudWatch table-level metric context where available, "
                "and correlates service or region-level Cost Explorer billing "
                "context where available, but does not collect item counts, "
                "backup storage size, table-level billing attribution, or "
                "workload owner evidence."
            ),
            (
                "metric_detail_mode can be set to summary for faster development "
                "scans, but consumed-capacity, throttle, latency, and system-error "
                "findings require full metric detail."
            ),
            (
                "autoscaling_detail_mode can be set to summary for faster "
                "development scans, but provisioned table or GSI autoscaling "
                "coverage findings require full autoscaling detail."
            ),
            (
                "table_detail_regional_mode can be set to billing-active for "
                "faster development scans; summarized regions keep table-name "
                "inventory only, while client-facing reviews should use full "
                "regional table detail."
            ),
            ("Does not recommend changing billing mode, capacity, indexes, streams, TTL, or point-in-time recovery without workload and recovery validation."),
        ),
        cloudwatch_namespaces_used=("AWS/DynamoDB",),
        metrics_used=(
            "ConsumedReadCapacityUnits",
            "ConsumedWriteCapacityUnits",
            "ReadThrottleEvents",
            "WriteThrottleEvents",
            "ThrottledRequests",
            "SystemErrors",
            "SuccessfulRequestLatency",
        ),
        may_incur_charges=False,
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Analyzes serialized DynamoDB region records and collected cost context without AWS clients."),
    ),
}

DYNAMODB_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "dynamodb",
    DYNAMODB_SCANNERS,
)
