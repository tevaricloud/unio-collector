"""Explicit rds_database SDK configuration and compact-summary field roles."""

from unio_collector.privacy.s3.fields import fields

RDS_DATABASE = {
    **fields("recommended_configuration.projectedUtilizationMetrics", "array", "safe_metadata"),
    **fields("raw_summary.fixture", "boolean", "safe_metadata"),
    **fields(
        (
            "raw_summary.currentStorageConfiguration.allocatedStorage raw_summary.currentStorageConfiguration.iops "
            "raw_summary.currentStorageConfiguration.maxAllocatedStorage "
            "raw_summary.currentStorageConfiguration.storageThroughput raw_summary.promotionTier "
            "recommended_configuration.rank recommended_configuration.storageConfiguration.allocatedStorage "
            "recommended_configuration.storageConfiguration.iops "
            "recommended_configuration.storageConfiguration.maxAllocatedStorage "
            "recommended_configuration.storageConfiguration.storageThroughput"
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
        ("raw_summary.lookbackPeriodInDays recommended_configuration.performanceRisk recommended_configuration.projectedUtilizationMetrics[].value"),
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
            "current_configuration raw_summary raw_summary.currentStorageConfiguration "
            "raw_summary.effectiveRecommendationPreferences recommended_configuration "
            "recommended_configuration.projectedUtilizationMetrics[] recommended_configuration.storageConfiguration"
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
    **fields("raw_summary.effectiveRecommendationPreferences.enhancedInfrastructureMetrics", "sdk_EnhancedInfrastructureMetrics", "safe_metadata"),
    **fields("raw_summary.idle", "sdk_Idle", "safe_metadata"),
    **fields("raw_summary.effectiveRecommendationPreferences.lookBackPeriod", "sdk_LookBackPeriodPreference", "safe_metadata"),
    **fields("raw_summary.currentInstancePerformanceRisk", "sdk_RDSCurrentInstancePerformanceRisk", "safe_metadata"),
    **fields("recommended_configuration.projectedUtilizationMetrics[].name", "sdk_RDSDBMetricName", "safe_metadata"),
    **fields("recommended_configuration.projectedUtilizationMetrics[].statistic", "sdk_RDSDBMetricStatistic", "safe_metadata"),
    **fields(
        ("raw_summary.currentStorageEstimatedMonthlyVolumeIOPsCostVariation recommended_configuration.estimatedMonthlyVolumeIOPsCostVariation"),
        "sdk_RDSEstimatedMonthlyVolumeIOPsCostVariation",
        "cost",
    ),
    **fields("", "sdk_RDSInstanceFinding", "safe_metadata"),
    **fields("raw_summary.instanceFinding", "sdk_RDSInstanceFinding", "safe_metadata", nullable=True),
    **fields("", "sdk_RDSStorageFinding", "safe_metadata"),
    **fields("raw_summary.storageFinding", "sdk_RDSStorageFinding", "safe_metadata", nullable=True),
    **fields("", "string", "arn"),
    **fields("raw_summary.resourceArn", "string", "arn", nullable=True),
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
    **fields("raw_summary.dbClusterIdentifier", "string", "resource_id"),
    **fields(
        (
            "current_configuration.instanceClass current_configuration.instanceType raw_summary.currentDBInstanceClass "
            "raw_summary.currentStorageConfiguration.storageType raw_summary.engine raw_summary.engineVersion "
            "raw_summary.instanceFindingReasonCodes raw_summary.instanceRecommendationOptions "
            "raw_summary.storageFindingReasonCodes raw_summary.storageRecommendationOptions raw_summary.tags "
            "raw_summary.utilizationMetrics recommended_configuration.dbInstanceClass "
            "recommended_configuration.instanceClass recommended_configuration.instanceType "
            "recommended_configuration.storageConfiguration.storageType"
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
