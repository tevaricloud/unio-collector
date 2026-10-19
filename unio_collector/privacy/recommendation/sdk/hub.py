"""Explicit hub SDK configuration and compact-summary field roles."""

from unio_collector.privacy.s3.fields import fields

HUB = {
    **fields("raw_summary.fixture raw_summary.restartNeeded raw_summary.rollbackPossible", "boolean", "safe_metadata"),
    **fields("raw_summary.recommendationLookbackPeriodInDays", "count", "safe_metadata"),
    **fields("raw_summary.estimatedMonthlyCost raw_summary.estimatedMonthlySavings raw_summary.estimatedSavingsPercentage", "finite_number", "cost"),
    **fields("current_configuration raw_summary recommended_configuration", "object", "safe_metadata"),
    **fields("raw_summary.source", "sdk_Source", "safe_metadata"),
    **fields("", "string", "arn"),
    **fields("raw_summary.resourceArn", "string", "arn", nullable=True),
    **fields("raw_summary.accountId", "string", "aws_account_id"),
    **fields("raw_summary.currencyCode", "string", "cost"),
    **fields("", "string", "region"),
    **fields("raw_summary.region", "string", "region", nullable=True),
    **fields("", "string", "resource_id"),
    **fields("raw_summary.recommendationId raw_summary.resourceId", "string", "resource_id", nullable=True),
    **fields(
        (
            "current_configuration.instanceClass current_configuration.instanceType "
            "raw_summary.currentResourceSummary raw_summary.recommendedResourceSummary raw_summary.tags "
            "recommended_configuration.instanceClass recommended_configuration.instanceType"
        ),
        "string",
        "resource_name",
    ),
    **fields(
        "raw_summary.actionType raw_summary.currentResourceType raw_summary.implementationEffort raw_summary.recommendedResourceType",
        "string",
        "resource_name",
        nullable=True,
    ),
    **fields(
        (
            "raw_summary.accountResourceArn raw_summary.confidence raw_summary.description raw_summary.finding "
            "raw_summary.recommendationIdentifier raw_summary.recommendationType raw_summary.resourceType "
            "raw_summary.service raw_summary.serviceName raw_summary.summary raw_summary.type"
        ),
        "string",
        "resource_name",
        nullable=True,
    ),
}
