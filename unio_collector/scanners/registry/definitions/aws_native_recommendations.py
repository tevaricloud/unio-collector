from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.source import ScannerDefinitionSource
from unio_collector.scanners.scanner.definition import ScannerDefinition

AWS_NATIVE_RECOMMENDATION_SCANNERS: dict[str, ScannerDefinition] = {
    "compute-optimizer-recommendation-review": ScannerDefinition(
        scanner_id="compute-optimizer-recommendation-review",
        display_name="Compute Optimizer recommendation review",
        description=(
            "Ingests visible AWS Compute Optimizer recommendations as "
            "read-only evidence for rightsizing, idle-resource, and "
            "optimization review. Recommendations are wrapped with owner "
            "validation and change-safety context; no AWS changes are made."
        ),
        aws_services=("AWS Compute Optimizer",),
        resource_types=(
            "EC2 recommendation",
            "EBS recommendation",
            "Lambda recommendation",
            "RDS recommendation",
            "ECS recommendation",
            "Idle resource recommendation",
        ),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "compute-optimizer:GetRecommendationSummaries",
            "compute-optimizer:GetEC2InstanceRecommendations",
            "compute-optimizer:GetEBSVolumeRecommendations",
            "compute-optimizer:GetLambdaFunctionRecommendations",
            "compute-optimizer:GetRDSDatabaseRecommendations",
            "compute-optimizer:GetECSServiceRecommendations",
            "compute-optimizer:GetIdleRecommendations",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "compute-optimizer:GetRecommendationSummaries",
            "compute-optimizer:GetEC2InstanceRecommendations",
            "compute-optimizer:GetEBSVolumeRecommendations",
            "compute-optimizer:GetLambdaFunctionRecommendations",
            "compute-optimizer:GetRDSDatabaseRecommendations",
            "compute-optimizer:GetECSServiceRecommendations",
            "compute-optimizer:GetIdleRecommendations",
        ),
        risk_level="medium",
        output_finding_types=("compute_optimizer_recommendation",),
        maturity="experimental",
        limitations=(
            "Compute Optimizer must be enabled and visible to the scan role.",
            "AWS recommendation confidence and savings estimates are evidence signals only; workload owners must validate before changes.",
            "The scanner records unavailable, permission-limited, and not-enabled states without failing the scan.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzes serialized AWS-native recommendation payloads without AWS clients; account id and warnings are carried in the payload."
        ),
    ),
    "cost-optimization-hub-recommendation-review": ScannerDefinition(
        scanner_id="cost-optimization-hub-recommendation-review",
        display_name="Cost Optimization Hub recommendation review",
        description=(
            "Ingests visible AWS Cost Optimization Hub recommendations as "
            "read-only evidence and enriches them with validation, action "
            "sequencing, change-safety, and automation context."
        ),
        aws_services=("AWS Cost Optimization Hub",),
        resource_types=("AWS-native cost optimization recommendation",),
        default_enabled=True,
        supports_regions=True,
        required_iam_actions=(
            "ec2:DescribeRegions",
            "cost-optimization-hub:ListRecommendations",
            "cost-optimization-hub:ListRecommendationSummaries",
            "cost-optimization-hub:GetRecommendation",
        ),
        required_permission_level="read_only",
        aws_api_calls=(
            "cost-optimization-hub:ListRecommendations",
            "cost-optimization-hub:ListRecommendationSummaries",
            "cost-optimization-hub:GetRecommendation",
        ),
        risk_level="medium",
        output_finding_types=("cost_optimization_hub_recommendation",),
        maturity="experimental",
        limitations=(
            "Cost Optimization Hub must be enabled and visible to the scan role.",
            "Recommendations are imported as evidence, not automatically accepted remediation actions.",
            "The scanner records unavailable, permission-limited, and not-enabled states without failing the scan.",
        ),
        analysis_boundary="strict_evidence_only_ready",
        analysis_boundary_reason=(
            "Analyzes serialized Cost Optimization Hub recommendation payloads without AWS clients; account id and warnings are carried in the payload."
        ),
    ),
}

AWS_NATIVE_RECOMMENDATION_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "aws_native_recommendations",
    AWS_NATIVE_RECOMMENDATION_SCANNERS,
)
