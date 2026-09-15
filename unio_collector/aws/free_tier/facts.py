"""Neutral Free Tier endpoint and provider operation/error-code predicates."""

FREE_TIER_REGION = "us-east-1"


def is_account_plan_error(error: str) -> bool:
    """Identify errors from the account-plan read operation."""
    return error.startswith("freetier:GetAccountPlanState:")


def is_account_plan_expected_absence_error(error: str) -> bool:
    """Identify the provider's missing account-plan response code."""
    return is_account_plan_error(error) and ": ResourceNotFoundException:" in error
