"""Explicit ebs_volume SDK configuration and compact-summary field roles."""

from unio_collector.privacy.s3.fields import fields

EBS_VOLUME = {
    **fields(
        ("current_configuration.rootVolume raw_summary.currentConfiguration.rootVolume raw_summary.fixture recommended_configuration.configuration.rootVolume"),
        "boolean",
        "safe_metadata",
    ),
    **fields(
        (
            "current_configuration.volumeBaselineIOPS current_configuration.volumeBaselineThroughput "
            "current_configuration.volumeBurstIOPS current_configuration.volumeBurstThroughput "
            "current_configuration.volumeSize raw_summary.currentConfiguration.volumeBaselineIOPS "
            "raw_summary.currentConfiguration.volumeBaselineThroughput raw_summary.currentConfiguration.volumeBurstIOPS "
            "raw_summary.currentConfiguration.volumeBurstThroughput raw_summary.currentConfiguration.volumeSize "
            "recommended_configuration.configuration.volumeBaselineIOPS "
            "recommended_configuration.configuration.volumeBaselineThroughput "
            "recommended_configuration.configuration.volumeBurstIOPS "
            "recommended_configuration.configuration.volumeBurstThroughput "
            "recommended_configuration.configuration.volumeSize recommended_configuration.rank"
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
    **fields("raw_summary.lookBackPeriodInDays recommended_configuration.performanceRisk", "finite_number", "safe_metadata"),
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
            "current_configuration raw_summary raw_summary.currentConfiguration "
            "raw_summary.effectiveRecommendationPreferences recommended_configuration "
            "recommended_configuration.configuration"
        ),
        "object",
        "safe_metadata",
    ),
    **fields(
        (
            "recommended_configuration.savingsOpportunity.estimatedMonthlySavings.currency "
            "recommended_configuration.savingsOpportunityAfterDiscounts.estimatedMonthlySavings.currency"
        ),
        "sdk_Currency",
        "cost",
    ),
    **fields("raw_summary.currentPerformanceRisk", "sdk_CurrentPerformanceRisk", "safe_metadata"),
    **fields("", "sdk_EBSFinding", "safe_metadata"),
    **fields("raw_summary.finding", "sdk_EBSFinding", "safe_metadata", nullable=True),
    **fields("raw_summary.effectiveRecommendationPreferences.lookBackPeriod", "sdk_LookBackPeriodPreference", "safe_metadata"),
    **fields("", "string", "arn"),
    **fields("raw_summary.volumeArn", "string", "arn", nullable=True),
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
            "current_configuration.instanceClass current_configuration.instanceType current_configuration.volumeType "
            "raw_summary.currentConfiguration.volumeType raw_summary.tags raw_summary.utilizationMetrics "
            "raw_summary.volumeRecommendationOptions recommended_configuration.configuration.volumeType "
            "recommended_configuration.instanceClass recommended_configuration.instanceType"
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
