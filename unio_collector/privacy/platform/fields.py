"""Exact neutral managed-platform fields without analytics-only usage DTOs."""

from unio_collector.privacy.s3.fields import fields

COMMON = {
    "": ("object", "safe_metadata", False),
    **fields("records regions", "array"),
    **fields("records[]", "object"),
    **fields("regions[] records[].region", "string", "region"),
    **fields("records[].account_id", "string", "aws_account_id"),
    **fields("records[].regional_cost_record_count", "count", "summary_count"),
    **fields("records[].service_current_cost records[].service_previous_cost records[].regional_current_cost", "money", "cost", nullable=True),
    **fields("records[].service_cost_currency records[].regional_cost_currency", "string", "cost", nullable=True),
    **fields("records[].permission_errors", "array", "removed_diagnostic"),
    **fields("records[].permission_errors[]", "string", "removed_diagnostic"),
}
