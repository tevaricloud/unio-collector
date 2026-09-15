from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

LIGHTSAIL_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "Lightsail instance",
    "Lightsail static IP",
    "Lightsail disk",
    "Lightsail database",
    "Lightsail load balancer",
    "Lightsail bucket",
    "Lightsail container service",
)

ROUTE53_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "Hosted zone",
    "Health check",
    "Traffic policy",
)

SNS_COST_GOVERNANCE_REVIEW_EVIDENCE = ("SNS topic",)

STEP_FUNCTIONS_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "State machine",
    "Activity",
)

SERVICE_COVERAGE_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "lightsail-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Lightsail cost governance review requires ec2:DescribeRegions to collect read-only Lightsail instance, "
                "Lightsail static IP, Lightsail disk, Lightsail database, Lightsail load balancer, Lightsail bucket, "
                "Lightsail container service evidence.",
                chargeable=False,
                evidence_categories=LIGHTSAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lightsail:GetInstances",
                "required",
                "Lightsail cost governance review requires lightsail:GetInstances to collect read-only Lightsail "
                "instance, Lightsail static IP, Lightsail disk, Lightsail database, Lightsail load balancer, Lightsail "
                "bucket, Lightsail container service evidence.",
                chargeable=False,
                evidence_categories=LIGHTSAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lightsail:GetInstances is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lightsail:GetStaticIps",
                "required",
                "Lightsail cost governance review requires lightsail:GetStaticIps to collect read-only Lightsail "
                "instance, Lightsail static IP, Lightsail disk, Lightsail database, Lightsail load balancer, Lightsail "
                "bucket, Lightsail container service evidence.",
                chargeable=False,
                evidence_categories=LIGHTSAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lightsail:GetStaticIps is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lightsail:GetDisks",
                "required",
                "Lightsail cost governance review requires lightsail:GetDisks to collect read-only Lightsail instance, "
                "Lightsail static IP, Lightsail disk, Lightsail database, Lightsail load balancer, Lightsail bucket, "
                "Lightsail container service evidence.",
                chargeable=False,
                evidence_categories=LIGHTSAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lightsail:GetDisks is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lightsail:GetLoadBalancers",
                "required",
                "Lightsail cost governance review requires lightsail:GetLoadBalancers to collect read-only "
                "Lightsail instance, Lightsail static IP, Lightsail disk, Lightsail database, Lightsail load "
                "balancer, Lightsail bucket, Lightsail container service evidence.",
                chargeable=False,
                evidence_categories=LIGHTSAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lightsail:GetLoadBalancers is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lightsail:GetRelationalDatabases",
                "required",
                "Lightsail cost governance review requires lightsail:GetRelationalDatabases to collect "
                "read-only Lightsail instance, Lightsail static IP, Lightsail disk, Lightsail database, "
                "Lightsail load balancer, Lightsail bucket, Lightsail container service evidence.",
                chargeable=False,
                evidence_categories=LIGHTSAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lightsail:GetRelationalDatabases is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lightsail:GetBuckets",
                "required",
                "Lightsail cost governance review requires lightsail:GetBuckets to collect read-only Lightsail instance, "
                "Lightsail static IP, Lightsail disk, Lightsail database, Lightsail load balancer, Lightsail bucket, "
                "Lightsail container service evidence.",
                chargeable=False,
                evidence_categories=LIGHTSAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lightsail:GetBuckets is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "lightsail:GetContainerServices",
                "required",
                "Lightsail cost governance review requires lightsail:GetContainerServices to collect read-only "
                "Lightsail instance, Lightsail static IP, Lightsail disk, Lightsail database, Lightsail load "
                "balancer, Lightsail bucket, Lightsail container service evidence.",
                chargeable=False,
                evidence_categories=LIGHTSAIL_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="lightsail:GetContainerServices is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "route53-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "route53:ListHostedZones",
                "required",
                "Route 53 cost governance review requires route53:ListHostedZones to collect read-only Hosted zone, Health check, Traffic policy evidence.",
                chargeable=False,
                evidence_categories=ROUTE53_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="route53:ListHostedZones is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "route53:ListHealthChecks",
                "required",
                "Route 53 cost governance review requires route53:ListHealthChecks to collect read-only Hosted zone, Health check, Traffic policy evidence.",
                chargeable=False,
                evidence_categories=ROUTE53_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="route53:ListHealthChecks is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "route53:ListTrafficPolicies",
                "required",
                "Route 53 cost governance review requires route53:ListTrafficPolicies to collect read-only Hosted zone, Health check, Traffic policy evidence.",
                chargeable=False,
                evidence_categories=ROUTE53_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="route53:ListTrafficPolicies is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "sns-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "SNS cost governance review requires ec2:DescribeRegions to collect read-only SNS topic evidence.",
                chargeable=False,
                evidence_categories=SNS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sns:ListTopics",
                "required",
                "SNS cost governance review requires sns:ListTopics to collect read-only SNS topic evidence.",
                chargeable=False,
                evidence_categories=SNS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sns:ListTopics is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sns:GetTopicAttributes",
                "required",
                "SNS cost governance review requires sns:GetTopicAttributes to collect read-only SNS topic evidence.",
                chargeable=False,
                evidence_categories=SNS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sns:GetTopicAttributes is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "sns:ListTagsForResource",
                "required",
                "SNS cost governance review requires sns:ListTagsForResource to collect read-only SNS topic evidence.",
                chargeable=False,
                evidence_categories=SNS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="sns:ListTagsForResource is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "step-functions-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Step Functions cost governance review requires ec2:DescribeRegions to collect read-only State machine, Activity evidence.",
                chargeable=False,
                evidence_categories=STEP_FUNCTIONS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "states:ListStateMachines",
                "required",
                "Step Functions cost governance review requires states:ListStateMachines to collect read-only State machine, Activity evidence.",
                chargeable=False,
                evidence_categories=STEP_FUNCTIONS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="states:ListStateMachines is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "states:ListActivities",
                "required",
                "Step Functions cost governance review requires states:ListActivities to collect read-only State machine, Activity evidence.",
                chargeable=False,
                evidence_categories=STEP_FUNCTIONS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="states:ListActivities is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "states:ListTagsForResource",
                "required",
                "Step Functions cost governance review requires states:ListTagsForResource to collect read-only State machine, Activity evidence.",
                chargeable=False,
                evidence_categories=STEP_FUNCTIONS_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="states:ListTagsForResource is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
