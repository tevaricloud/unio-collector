"""Explicit idle SDK configuration and compact-summary field roles."""

from unio_collector.privacy.s3.fields import fields

IDLE = {
    **fields("raw_summary.fixture", "boolean", "safe_metadata"),
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
        ("raw_summary.savingsOpportunity.savingsOpportunityPercentage raw_summary.savingsOpportunityAfterDiscounts.savingsOpportunityPercentage"),
        "finite_number",
        "cost",
    ),
    **fields("raw_summary.lookBackPeriodInDays", "finite_number", "safe_metadata"),
    **fields(
        ("current_configuration raw_summary raw_summary.savingsOpportunity raw_summary.savingsOpportunityAfterDiscounts recommended_configuration"),
        "object",
        "safe_metadata",
    ),
    **fields("", "sdk_IdleFinding", "safe_metadata"),
    **fields("raw_summary.finding", "sdk_IdleFinding", "safe_metadata", nullable=True),
    **fields("", "sdk_IdleRecommendationResourceType", "safe_metadata"),
    **fields("raw_summary.resourceType", "sdk_IdleRecommendationResourceType", "safe_metadata", nullable=True),
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
    **fields(
        (
            "current_configuration.instanceClass current_configuration.instanceType raw_summary.findingDescription "
            "raw_summary.tags raw_summary.utilizationMetrics recommended_configuration.instanceClass "
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
