"""Exact read-only operations used by AWS-native recommendation collection."""

AWS_NATIVE_ACTIONS = {
    "get_recommendation_summaries": "compute-optimizer:GetRecommendationSummaries",
    "get_ec2_instance_recommendations": "compute-optimizer:GetEC2InstanceRecommendations",
    "get_ebs_volume_recommendations": "compute-optimizer:GetEBSVolumeRecommendations",
    "get_lambda_function_recommendations": "compute-optimizer:GetLambdaFunctionRecommendations",
    "get_rds_database_recommendations": "compute-optimizer:GetRDSDatabaseRecommendations",
    "get_ecs_service_recommendations": "compute-optimizer:GetECSServiceRecommendations",
    "get_idle_recommendations": "compute-optimizer:GetIdleRecommendations",
    "list_recommendations": "cost-optimization-hub:ListRecommendations",
    "list_recommendation_summaries": "cost-optimization-hub:ListRecommendationSummaries",
}
