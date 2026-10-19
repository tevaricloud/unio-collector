"""Finite record identities and exact shared recommendation envelope fields."""

from __future__ import annotations

from unio_collector.privacy.s3.fields import fields

SCANNERS = {"compute-optimizer-recommendation-review": "compute_optimizer", "cost-optimization-hub-recommendation-review": "cost_optimization_hub"}
SOURCE_TYPES = {
    "ec2_instance": ("Amazon EC2", "EC2 instance"),
    "ebs_volume": ("Amazon EBS", "EBS volume"),
    "lambda_function": ("AWS Lambda", "Lambda function"),
    "rds_database": ("Amazon RDS", "RDS database"),
    "ecs_service": ("Amazon ECS", "ECS service"),
    "idle": ("AWS", "Idle resource"),
}
VOCABULARIES = {
    "source": frozenset(SCANNERS.values()),
    "status": frozenset({"recorded", "recorded_no_recommendations", "partial", "capped", "unavailable", "permission_limited", "not_enabled"}),
    "collection_status": frozenset({"complete", "partial", "capped", "unavailable", "permission_limited", "not_enabled"}),
    "operation_status": frozenset({"complete", "partial", "capped", "unavailable", "permission_limited", "not_enabled", "unsupported_region"}),
    "scope_operation": frozenset({"region_resolution", "endpoint_resolution"}),
    "endpoint_strategy": frozenset({"explicit_region_override", "sdk_service_regions_intersected_with_account_enabled_regions"}),
    "api_action": frozenset(
        {
            "compute-optimizer:GetRecommendationSummaries",
            "compute-optimizer:GetEC2InstanceRecommendations",
            "compute-optimizer:GetEBSVolumeRecommendations",
            "compute-optimizer:GetLambdaFunctionRecommendations",
            "compute-optimizer:GetRDSDatabaseRecommendations",
            "compute-optimizer:GetECSServiceRecommendations",
            "compute-optimizer:GetIdleRecommendations",
            "cost-optimization-hub:ListRecommendations",
            "cost-optimization-hub:ListRecommendationSummaries",
        }
    ),
}
ROOT_FIELDS = {
    "": ("object", "safe_metadata", False),
    **fields("source", "source"),
    **fields("status", "status"),
    **fields("account_id", "string", "aws_account_id"),
    **fields("regions metadata.selected_regions metadata.unsupported_regions", "array"),
    **fields("regions[] metadata.selected_regions[] metadata.unsupported_regions[]", "string", "region"),
    **fields("records summaries warnings limitations metadata.operation_statuses", "array"),
    **fields("records[] summaries[] metadata metadata.operation_statuses[]", "object"),
    **fields("warnings[] limitations[] metadata.origin metadata.operation_statuses[].error_code", "string", "resource_name"),
    **fields(
        (
            "recommendation_count summary_count metadata.record_limit metadata.record_budget_used metadata.summary_limit "
            "metadata.operation_statuses[].retained_count metadata.operation_statuses[].observed_count "
            "metadata.operation_statuses[].omitted_count"
        ),
        "count",
    ),
    **fields("evidence_version", "version"),
    **fields("metadata.collection_status", "collection_status"),
    **fields("metadata.operation_statuses[].api_action", "api_action"),
    **fields("metadata.operation_statuses[].status", "operation_status"),
    **fields("metadata.operation_statuses[].type", "scope_operation"),
    **fields("metadata.operation_statuses[].region", "string", "region"),
    **fields("metadata.operation_statuses[].collection_stopped metadata.explicit_region_scope", "boolean"),
    **fields("metadata.endpoint_strategy", "endpoint_strategy"),
}
RECORD_FIELDS = {
    "records[]": ("object", "safe_metadata", False),
    **fields("records[].source", "source"),
    **fields("records[].recommendation_id records[].resource_id", "string", "resource_id"),
    **fields("records[].resource_arn", "string", "arn", nullable=True),
    **fields("records[].region", "string", "region"),
    **fields("records[].service records[].resource_type records[].recommendation_type records[].finding records[].confidence", "string", "resource_name"),
    **fields("records[].estimated_monthly_savings", "financial_string", "cost", nullable=True),
    **fields("records[].currency", "string", "cost", nullable=True),
    **fields("records[].current_configuration records[].recommended_configuration records[].raw_summary", "object"),
}
