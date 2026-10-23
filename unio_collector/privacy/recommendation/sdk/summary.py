"""Exact Compute Optimizer and Cost Hub summary fields; financial roles are separate."""

from unio_collector.privacy.s3.fields import fields

COMPUTE_OPTIMIZER_SUMMARY = {
    **fields("summaries[].inferredWorkloadSavings summaries[].inferredWorkloadSavings[].inferredWorkloadTypes", "array", "cost"),
    **fields("summaries[].idleSummaries summaries[].summaries summaries[].summaries[].reasonCodeSummaries", "array", "safe_metadata"),
    **fields(
        (
            "summaries[].currentPerformanceRiskRatings.high summaries[].currentPerformanceRiskRatings.low "
            "summaries[].currentPerformanceRiskRatings.medium summaries[].currentPerformanceRiskRatings.veryLow"
        ),
        "count",
        "safe_metadata",
    ),
    **fields(
        (
            "summaries[].aggregatedSavingsOpportunity.estimatedMonthlySavings.value "
            "summaries[].aggregatedSavingsOpportunity.savingsOpportunityPercentage "
            "summaries[].idleSavingsOpportunity.estimatedMonthlySavings.value "
            "summaries[].idleSavingsOpportunity.savingsOpportunityPercentage "
            "summaries[].inferredWorkloadSavings[].estimatedMonthlySavings.value "
            "summaries[].savingsOpportunity.estimatedMonthlySavings.value "
            "summaries[].savingsOpportunity.savingsOpportunityPercentage"
        ),
        "finite_number",
        "cost",
    ),
    **fields(
        ("summaries[].idleSummaries[].value summaries[].summaries[].reasonCodeSummaries[].value summaries[].summaries[].value"),
        "finite_number",
        "safe_metadata",
    ),
    **fields(
        (
            "summaries[].aggregatedSavingsOpportunity summaries[].aggregatedSavingsOpportunity.estimatedMonthlySavings "
            "summaries[].idleSavingsOpportunity summaries[].idleSavingsOpportunity.estimatedMonthlySavings "
            "summaries[].inferredWorkloadSavings[] summaries[].inferredWorkloadSavings[].estimatedMonthlySavings "
            "summaries[].savingsOpportunity summaries[].savingsOpportunity.estimatedMonthlySavings"
        ),
        "object",
        "cost",
    ),
    **fields(
        (
            "summaries[] summaries[].currentPerformanceRiskRatings summaries[].idleSummaries[] summaries[].summaries[] "
            "summaries[].summaries[].reasonCodeSummaries[]"
        ),
        "object",
        "safe_metadata",
    ),
    **fields(
        (
            "summaries[].aggregatedSavingsOpportunity.estimatedMonthlySavings.currency "
            "summaries[].idleSavingsOpportunity.estimatedMonthlySavings.currency "
            "summaries[].inferredWorkloadSavings[].estimatedMonthlySavings.currency "
            "summaries[].savingsOpportunity.estimatedMonthlySavings.currency"
        ),
        "sdk_Currency",
        "cost",
    ),
    **fields("summaries[].summaries[].name", "sdk_Finding", "safe_metadata"),
    **fields("summaries[].summaries[].reasonCodeSummaries[].name", "sdk_FindingReasonCode", "safe_metadata"),
    **fields("summaries[].idleSummaries[].name", "sdk_IdleFinding", "safe_metadata"),
    **fields("summaries[].inferredWorkloadSavings[].inferredWorkloadTypes[]", "sdk_InferredWorkloadType", "cost"),
    **fields("summaries[].recommendationResourceType", "sdk_RecommendationSourceType", "safe_metadata"),
    **fields("summaries[].accountId", "string", "aws_account_id"),
}

COST_OPTIMIZATION_HUB_SUMMARY = {
    **fields("summaries[].recommendationCount", "count", "safe_metadata"),
    **fields("summaries[].estimatedMonthlySavings", "finite_number", "cost"),
    **fields("summaries[]", "object", "safe_metadata"),
    **fields("summaries[].group", "string", "resource_name"),
}
