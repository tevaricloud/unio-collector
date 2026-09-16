from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

SERVICE_COVERAGE_SCANNERS: dict[str, ScannerDefinition] = {
    "route53-cost-governance-review": ScannerDefinition(
        scanner_id="route53-cost-governance-review",
        display_name="Route 53 cost governance review",
        description=("Reviews Route 53 hosted zone, health check, and traffic policy metadata as DNS cost-governance evidence."),
        aws_services=("Amazon Route 53",),
        resource_types=("Hosted zone", "Health check", "Traffic policy"),
        default_enabled=True,
        supports_regions=False,
        required_iam_actions=(
            "route53:ListHostedZones",
            "route53:ListHealthChecks",
            "route53:ListTrafficPolicies",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "route53:ListHostedZones",
            "route53:ListHealthChecks",
            "route53:ListTrafficPolicies",
        ),
        risk_level="low",
        output_finding_types=("route53_health_check_cost_review",),
        maturity="experimental",
        limitations=(
            "Does not change DNS, hosted zones, records, health checks, or traffic policies.",
            "Does not collect query volume, resolver query logs, or resource-level Route 53 billing attribution.",
            "Hosted zone presence alone is recorded as coverage evidence, not a finding.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects Route 53 service coverage records with account metadata and analyzes only serialized evidence without AWS clients."
        ),
    ),
    "step-functions-cost-governance-review": ScannerDefinition(
        scanner_id="step-functions-cost-governance-review",
        display_name="Step Functions cost governance review",
        description=("Reviews Step Functions state machine, activity, and tag metadata as workflow cost-governance evidence."),
        aws_services=("AWS Step Functions",),
        resource_types=("State machine", "Activity"),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "states:ListStateMachines",
            "states:ListActivities",
            "states:ListTagsForResource",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "stepfunctions:ListStateMachines",
            "stepfunctions:ListActivities",
            "stepfunctions:ListTagsForResource",
        ),
        risk_level="low",
        output_finding_types=("step_functions_state_machine_tagging_review",),
        maturity="experimental",
        limitations=(
            "Does not start, stop, update, delete, or execute workflows.",
            "Does not collect execution history, transition counts, log volume, or exact resource-level billing attribution.",
            "Missing tags are ownership signals, not proof that a workflow is waste.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects Step Functions service coverage records with account metadata and analyzes only serialized evidence without AWS clients."
        ),
    ),
    "lightsail-cost-governance-review": ScannerDefinition(
        scanner_id="lightsail-cost-governance-review",
        display_name="Lightsail cost governance review",
        description=(
            "Reviews Lightsail instances, static IPs, disks, databases, load "
            "balancers, buckets, and container services as simplified workload "
            "cost-governance evidence."
        ),
        aws_services=("Amazon Lightsail",),
        resource_types=(
            "Lightsail instance",
            "Lightsail static IP",
            "Lightsail disk",
            "Lightsail database",
            "Lightsail load balancer",
            "Lightsail bucket",
            "Lightsail container service",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "lightsail:GetInstances",
            "lightsail:GetStaticIps",
            "lightsail:GetDisks",
            "lightsail:GetLoadBalancers",
            "lightsail:GetRelationalDatabases",
            "lightsail:GetBuckets",
            "lightsail:GetContainerServices",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "lightsail:GetInstances",
            "lightsail:GetStaticIps",
            "lightsail:GetDisks",
            "lightsail:GetLoadBalancers",
            "lightsail:GetRelationalDatabases",
            "lightsail:GetBuckets",
            "lightsail:GetContainerServices",
        ),
        risk_level="medium",
        output_finding_types=(
            "lightsail_unattached_static_ip_review",
            "lightsail_unattached_disk_review",
            "lightsail_stopped_instance_review",
        ),
        maturity="experimental",
        limitations=(
            "Does not start, stop, delete, snapshot, resize, or modify Lightsail resources.",
            "Does not collect utilization metrics, transfer usage, snapshot inventory, or exact resource-level billing attribution.",
            "Stopped, unattached, or unassigned resources require owner validation before cleanup.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Collects Lightsail service coverage records with account metadata and analyzes only serialized evidence without AWS clients."
        ),
    ),
    "sns-cost-governance-review": ScannerDefinition(
        scanner_id="sns-cost-governance-review",
        display_name="SNS cost governance review",
        description=("Reviews SNS topic, subscription count, encryption, and tag metadata as notification cost-governance evidence."),
        aws_services=(
            "Amazon Simple Notification Service",
            "Amazon SNS",
        ),
        resource_types=("SNS topic",),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "sns:ListTopics",
            "sns:GetTopicAttributes",
            "sns:ListTagsForResource",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "ec2:DescribeRegions",
            "sns:ListTopics",
            "sns:GetTopicAttributes",
            "sns:ListTagsForResource",
        ),
        risk_level="low",
        output_finding_types=("sns_topic_without_subscriptions_review",),
        maturity="experimental",
        limitations=(
            "Does not publish messages, subscribe endpoints, delete topics, or change policies.",
            "Does not collect message publish volume, delivery logs, SMS spend, or exact resource-level billing attribution.",
            "A topic with no confirmed subscriptions can still be intentionally retained and must be owner-validated.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=("Collects SNS service coverage records with account metadata and analyzes only serialized evidence without AWS clients."),
    ),
}

SERVICE_COVERAGE_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "service_coverage",
    SERVICE_COVERAGE_SCANNERS,
)
