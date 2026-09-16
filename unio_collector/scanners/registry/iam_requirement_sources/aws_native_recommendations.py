from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

COMPUTE_OPTIMIZER_RECOMMENDATION_REVIEW_EVIDENCE = (
    "EC2 recommendation",
    "EBS recommendation",
    "Lambda recommendation",
    "RDS recommendation",
    "ECS recommendation",
    "Idle resource recommendation",
)

COST_OPTIMIZATION_HUB_RECOMMENDATION_REVIEW_EVIDENCE = ("AWS-native cost optimization recommendation",)

AWS_NATIVE_RECOMMENDATIONS_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "compute-optimizer-recommendation-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Compute Optimizer recommendation review requires ec2:DescribeRegions to collect read-only EC2 "
                "recommendation, EBS recommendation, Lambda recommendation, RDS recommendation, ECS recommendation, Idle "
                "resource recommendation evidence.",
                chargeable=False,
                evidence_categories=COMPUTE_OPTIMIZER_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "compute-optimizer:GetRecommendationSummaries",
                "required",
                "Compute Optimizer recommendation review requires "
                "compute-optimizer:GetRecommendationSummaries to collect read-only EC2 "
                "recommendation, EBS recommendation, Lambda recommendation, RDS recommendation, "
                "ECS recommendation, Idle resource recommendation evidence.",
                chargeable=False,
                evidence_categories=COMPUTE_OPTIMIZER_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="compute-optimizer:GetRecommendationSummaries is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "compute-optimizer:GetEC2InstanceRecommendations",
                "required",
                "Compute Optimizer recommendation review requires "
                "compute-optimizer:GetEC2InstanceRecommendations to collect read-only EC2 "
                "recommendation, EBS recommendation, Lambda recommendation, RDS "
                "recommendation, ECS recommendation, Idle resource recommendation evidence.",
                chargeable=False,
                evidence_categories=COMPUTE_OPTIMIZER_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="compute-optimizer:GetEC2InstanceRecommendations is rendered with Resource='*' because the scanner IAM metadata does "
                "not declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "compute-optimizer:GetEBSVolumeRecommendations",
                "required",
                "Compute Optimizer recommendation review requires "
                "compute-optimizer:GetEBSVolumeRecommendations to collect read-only EC2 "
                "recommendation, EBS recommendation, Lambda recommendation, RDS recommendation, "
                "ECS recommendation, Idle resource recommendation evidence.",
                chargeable=False,
                evidence_categories=COMPUTE_OPTIMIZER_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="compute-optimizer:GetEBSVolumeRecommendations is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "compute-optimizer:GetLambdaFunctionRecommendations",
                "required",
                "Compute Optimizer recommendation review requires "
                "compute-optimizer:GetLambdaFunctionRecommendations to collect read-only "
                "EC2 recommendation, EBS recommendation, Lambda recommendation, RDS "
                "recommendation, ECS recommendation, Idle resource recommendation evidence.",
                chargeable=False,
                evidence_categories=COMPUTE_OPTIMIZER_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="compute-optimizer:GetLambdaFunctionRecommendations is rendered with Resource='*' because the scanner IAM metadata "
                "does not declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "compute-optimizer:GetRDSDatabaseRecommendations",
                "required",
                "Compute Optimizer recommendation review requires "
                "compute-optimizer:GetRDSDatabaseRecommendations to collect read-only EC2 "
                "recommendation, EBS recommendation, Lambda recommendation, RDS "
                "recommendation, ECS recommendation, Idle resource recommendation evidence.",
                chargeable=False,
                evidence_categories=COMPUTE_OPTIMIZER_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="compute-optimizer:GetRDSDatabaseRecommendations is rendered with Resource='*' because the scanner IAM metadata does "
                "not declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "compute-optimizer:GetECSServiceRecommendations",
                "required",
                "Compute Optimizer recommendation review requires "
                "compute-optimizer:GetECSServiceRecommendations to collect read-only EC2 "
                "recommendation, EBS recommendation, Lambda recommendation, RDS "
                "recommendation, ECS recommendation, Idle resource recommendation evidence.",
                chargeable=False,
                evidence_categories=COMPUTE_OPTIMIZER_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="compute-optimizer:GetECSServiceRecommendations is rendered with Resource='*' because the scanner IAM metadata does "
                "not declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "compute-optimizer:GetIdleRecommendations",
                "required",
                "Compute Optimizer recommendation review requires "
                "compute-optimizer:GetIdleRecommendations to collect read-only EC2 recommendation, "
                "EBS recommendation, Lambda recommendation, RDS recommendation, ECS recommendation, "
                "Idle resource recommendation evidence.",
                chargeable=False,
                evidence_categories=COMPUTE_OPTIMIZER_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="compute-optimizer:GetIdleRecommendations is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
    "cost-optimization-hub-recommendation-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ec2:DescribeRegions",
                "required",
                "Cost Optimization Hub recommendation review requires ec2:DescribeRegions to collect read-only AWS-native "
                "cost optimization recommendation evidence.",
                chargeable=False,
                evidence_categories=COST_OPTIMIZATION_HUB_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ec2:DescribeRegions is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cost-optimization-hub:ListRecommendations",
                "required",
                "Cost Optimization Hub recommendation review requires "
                "cost-optimization-hub:ListRecommendations to collect read-only AWS-native cost "
                "optimization recommendation evidence.",
                chargeable=False,
                evidence_categories=COST_OPTIMIZATION_HUB_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cost-optimization-hub:ListRecommendations is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cost-optimization-hub:ListRecommendationSummaries",
                "required",
                "Cost Optimization Hub recommendation review requires "
                "cost-optimization-hub:ListRecommendationSummaries to collect read-only "
                "AWS-native cost optimization recommendation evidence.",
                chargeable=False,
                evidence_categories=COST_OPTIMIZATION_HUB_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cost-optimization-hub:ListRecommendationSummaries is rendered with Resource='*' because the scanner IAM metadata does "
                "not declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
            Req(
                "cost-optimization-hub:GetRecommendation",
                "required",
                "Cost Optimization Hub recommendation review requires "
                "cost-optimization-hub:GetRecommendation to collect read-only AWS-native cost "
                "optimization recommendation evidence.",
                chargeable=False,
                evidence_categories=COST_OPTIMIZATION_HUB_RECOMMENDATION_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="cost-optimization-hub:GetRecommendation is rendered with Resource='*' because the scanner IAM metadata does not "
                "declare safe resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
