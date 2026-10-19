"""Explicit ecs_service SDK configuration and compact-summary field roles."""

from unio_collector.privacy.s3.fields import fields

ECS_SERVICE = {
    **fields("recommended_configuration.containerRecommendations recommended_configuration.projectedUtilizationMetrics", "array", "safe_metadata"),
    **fields("raw_summary.fixture", "boolean", "safe_metadata"),
    **fields(
        (
            "raw_summary.currentServiceConfiguration.cpu raw_summary.currentServiceConfiguration.memory "
            "recommended_configuration.containerRecommendations[].cpu "
            "recommended_configuration.containerRecommendations[].memorySizeConfiguration.memory "
            "recommended_configuration.containerRecommendations[].memorySizeConfiguration.memoryReservation "
            "recommended_configuration.cpu recommended_configuration.memory"
        ),
        "count",
        "safe_metadata",
    ),
    **fields(
        (
            "recommended_configuration.estimatedMonthlySavings.amount "
            "recommended_configuration.estimatedMonthlySavings.estimatedMonthlySavings "
            "recommended_configuration.estimatedMonthlySavings.estimatedSavings "
            "recommended_configuration.estimatedMonthlySavings.value "
            "recommended_configuration.estimatedMonthlySavingsValue.amount "
            "recommended_configuration.estimatedMonthlySavingsValue.estimatedMonthlySavings "
            "recommended_configuration.estimatedMonthlySavingsValue.estimatedSavings "
            "recommended_configuration.estimatedMonthlySavingsValue.value recommended_configuration.estimatedSavings.amount "
            "recommended_configuration.estimatedSavings.estimatedMonthlySavings "
            "recommended_configuration.estimatedSavings.estimatedSavings recommended_configuration.estimatedSavings.value"
        ),
        "financial_scalar",
        "cost",
    ),
    **fields(
        ("recommended_configuration.estimatedMonthlySavings recommended_configuration.estimatedMonthlySavingsValue recommended_configuration.estimatedSavings"),
        "financial_union",
        "cost",
    ),
    **fields(
        (
            "recommended_configuration.savingsOpportunity.estimatedMonthlySavings.value "
            "recommended_configuration.savingsOpportunity.savingsOpportunityPercentage "
            "recommended_configuration.savingsOpportunityAfterDiscounts.estimatedMonthlySavings.value "
            "recommended_configuration.savingsOpportunityAfterDiscounts.savingsOpportunityPercentage"
        ),
        "finite_number",
        "cost",
    ),
    **fields(
        (
            "raw_summary.lookbackPeriodInDays recommended_configuration.projectedUtilizationMetrics[].lowerBoundValue "
            "recommended_configuration.projectedUtilizationMetrics[].upperBoundValue"
        ),
        "finite_number",
        "safe_metadata",
    ),
    **fields(
        (
            "recommended_configuration.savingsOpportunity "
            "recommended_configuration.savingsOpportunity.estimatedMonthlySavings "
            "recommended_configuration.savingsOpportunityAfterDiscounts "
            "recommended_configuration.savingsOpportunityAfterDiscounts.estimatedMonthlySavings"
        ),
        "object",
        "cost",
    ),
    **fields(
        (
            "current_configuration raw_summary raw_summary.currentServiceConfiguration "
            "raw_summary.effectiveRecommendationPreferences recommended_configuration "
            "recommended_configuration.containerRecommendations[] "
            "recommended_configuration.containerRecommendations[].memorySizeConfiguration "
            "recommended_configuration.projectedUtilizationMetrics[]"
        ),
        "object",
        "safe_metadata",
    ),
    **fields("raw_summary.currentServiceConfiguration.autoScalingConfiguration", "sdk_AutoScalingConfiguration", "safe_metadata"),
    **fields(
        (
            "recommended_configuration.savingsOpportunity.estimatedMonthlySavings.currency "
            "recommended_configuration.savingsOpportunityAfterDiscounts.estimatedMonthlySavings.currency"
        ),
        "sdk_Currency",
        "cost",
    ),
    **fields("raw_summary.currentPerformanceRisk", "sdk_CurrentPerformanceRisk", "safe_metadata"),
    **fields("raw_summary.launchType", "sdk_ECSServiceLaunchType", "safe_metadata"),
    **fields("recommended_configuration.projectedUtilizationMetrics[].name", "sdk_ECSServiceMetricName", "safe_metadata"),
    **fields("recommended_configuration.projectedUtilizationMetrics[].statistic", "sdk_ECSServiceMetricStatistic", "safe_metadata"),
    **fields("", "sdk_ECSServiceRecommendationFinding", "safe_metadata"),
    **fields("raw_summary.finding", "sdk_ECSServiceRecommendationFinding", "safe_metadata", nullable=True),
    **fields("raw_summary.effectiveRecommendationPreferences.lookBackPeriod", "sdk_LookBackPeriodPreference", "safe_metadata"),
    **fields("raw_summary.currentServiceConfiguration.taskDefinitionArn", "string", "arn"),
    **fields("raw_summary.serviceArn", "string", "arn", nullable=True),
    **fields("raw_summary.accountId", "string", "aws_account_id"),
    **fields(
        (
            "recommended_configuration.estimatedMonthlySavings.currency "
            "recommended_configuration.estimatedMonthlySavings.currencyCode "
            "recommended_configuration.estimatedMonthlySavingsValue.currency "
            "recommended_configuration.estimatedMonthlySavingsValue.currencyCode "
            "recommended_configuration.estimatedSavings.currency recommended_configuration.estimatedSavings.currencyCode"
        ),
        "string",
        "cost",
    ),
    **fields(
        (
            "current_configuration.instanceClass current_configuration.instanceType raw_summary.findingReasonCodes "
            "raw_summary.serviceRecommendationOptions raw_summary.tags raw_summary.utilizationMetrics "
            "recommended_configuration.containerRecommendations[].containerName recommended_configuration.instanceClass "
            "recommended_configuration.instanceType"
        ),
        "string",
        "resource_name",
    ),
    **fields(
        (
            "raw_summary.confidence raw_summary.dbInstanceIdentifier raw_summary.findingReasonCode raw_summary.instanceName "
            "raw_summary.resourceId raw_summary.serviceName"
        ),
        "string",
        "resource_name",
        nullable=True,
    ),
}
