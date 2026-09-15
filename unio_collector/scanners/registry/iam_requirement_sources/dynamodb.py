from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE = (
    "DynamoDB table",
    "DynamoDB global secondary index",
    "Application Auto Scaling target",
)

DYNAMODB_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "dynamodb-cost-governance-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "DynamoDB cost governance review requires ec2:DescribeRegions to collect read-only DynamoDB table, "
                "DynamoDB global secondary index, Application Auto Scaling target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "dynamodb:ListTables",
                "required",
                "DynamoDB cost governance review requires dynamodb:ListTables to collect read-only DynamoDB table, "
                "DynamoDB global secondary index, Application Auto Scaling target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="dynamodb:ListTables is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "dynamodb:DescribeTable",
                "required",
                "DynamoDB cost governance review requires dynamodb:DescribeTable to collect read-only DynamoDB table, "
                "DynamoDB global secondary index, Application Auto Scaling target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="dynamodb:DescribeTable is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "dynamodb:DescribeContinuousBackups",
                "required",
                "DynamoDB cost governance review requires dynamodb:DescribeContinuousBackups to collect "
                "read-only DynamoDB table, DynamoDB global secondary index, Application Auto Scaling "
                "target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="dynamodb:DescribeContinuousBackups is rendered with Resource='*' because the scanner IAM metadata does not declare "
                "safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "dynamodb:DescribeTimeToLive",
                "required",
                "DynamoDB cost governance review requires dynamodb:DescribeTimeToLive to collect read-only "
                "DynamoDB table, DynamoDB global secondary index, Application Auto Scaling target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="dynamodb:DescribeTimeToLive is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "dynamodb:ListTagsOfResource",
                "required",
                "DynamoDB cost governance review requires dynamodb:ListTagsOfResource to collect read-only "
                "DynamoDB table, DynamoDB global secondary index, Application Auto Scaling target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="dynamodb:ListTagsOfResource is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "tag:GetResources",
                "required",
                "DynamoDB cost governance review requires tag:GetResources to collect read-only DynamoDB table, DynamoDB "
                "global secondary index, Application Auto Scaling target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="tag:GetResources is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "application-autoscaling:DescribeScalableTargets",
                "required",
                "DynamoDB cost governance review requires "
                "application-autoscaling:DescribeScalableTargets to collect read-only "
                "DynamoDB table, DynamoDB global secondary index, Application Auto Scaling "
                "target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="application-autoscaling:DescribeScalableTargets is rendered with Resource='*' because the scanner IAM metadata does "
                "not declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "application-autoscaling:DescribeScalingPolicies",
                "required",
                "DynamoDB cost governance review requires "
                "application-autoscaling:DescribeScalingPolicies to collect read-only "
                "DynamoDB table, DynamoDB global secondary index, Application Auto Scaling "
                "target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="application-autoscaling:DescribeScalingPolicies is rendered with Resource='*' because the scanner IAM metadata does "
                "not declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cloudwatch:GetMetricData",
                "required",
                "DynamoDB cost governance review requires cloudwatch:GetMetricData to collect read-only DynamoDB "
                "table, DynamoDB global secondary index, Application Auto Scaling target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cloudwatch:GetMetricData is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "ce:GetCostAndUsage",
                "required",
                "DynamoDB cost governance review requires ce:GetCostAndUsage to collect read-only DynamoDB table, DynamoDB "
                "global secondary index, Application Auto Scaling target evidence.",
                chargeable=False,
                evidence_categories=DYNAMODB_COST_GOVERNANCE_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
