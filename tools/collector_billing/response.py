"""Pinned SDK output shapes for the six read-only billing operations."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

OPERATIONS = {
    "describe_budgets": ("budgets", "DescribeBudgets", "Budgets"),
    "describe_notifications_for_budget": ("budgets", "DescribeNotificationsForBudget", "Notifications"),
    "describe_subscribers_for_notification": ("budgets", "DescribeSubscribersForNotification", "Subscribers"),
    "get_anomaly_monitors": ("ce", "GetAnomalyMonitors", "AnomalyMonitors"),
    "get_anomaly_subscriptions": ("ce", "GetAnomalySubscriptions", "AnomalySubscriptions"),
    "describe_alarms": ("cloudwatch", "DescribeAlarms", "MetricAlarms"),
}
VARIANTS = (
    "success",
    "empty",
    "optional",
    "denied",
    "unavailable",
    "failure",
    "partial",
    "summary",
    "budgets_only",
    "adversarial",
    "null_field",
    "malformed",
    "unknown",
    "expression_and",
    "expression_or",
    "expression_not",
    "expression_tags",
    "expression_categories",
    "sliding_window",
    "later_page",
)


MAX_RECURSIVE_EXPRESSIONS = 2
SAMPLE_COUNT = 2


class BillingSdkShape(Protocol):
    """Read-only view of installed SDK data, never an SDK client."""

    name: str
    required_members: list[str]
    type_name: str
    metadata: dict[str, object]
    is_tagged_union: bool
    members: dict[str, BillingSdkShape]
    member: BillingSdkShape
    value: BillingSdkShape


def _members(shape: BillingSdkShape, ancestors: tuple[str, ...], variant: str) -> list[tuple[str, BillingSdkShape]]:
    """Construct supported single expression operators and tagged-union branches."""
    members = list(shape.members.items())
    if shape.name == "Expression" and "Dimensions" in shape.members:
        selector = {
            "expression_and": "And",
            "expression_or": "Or",
            "expression_not": "Not",
            "expression_tags": "Tags",
            "expression_categories": "CostCategories",
        }.get(variant, "Dimensions")
        if ancestors.count(shape.name) > 0:
            selector = "Dimensions"
        members = [(selector, shape.members[selector])]
    if shape.is_tagged_union:
        members = members[-1:] if variant == "sliding_window" else members[:1]
    return members


def sample(shape: BillingSdkShape, key: str = "", ancestors: tuple[str, ...] = (), variant: str = "success") -> object:
    """Populate actual pinned SDK fields; recursive choices remain bounded."""
    if shape.type_name == "structure":
        if ancestors.count(shape.name) >= MAX_RECURSIVE_EXPRESSIONS:
            return {}
        return {name: sample(child, name, (*ancestors, shape.name), variant) for name, child in _members(shape, ancestors, variant)}
    if shape.type_name == "list":
        return [sample(shape.member, key, ancestors, variant)]
    if shape.type_name == "map":
        return {"1735689600" if shape.name == "PlannedBudgetLimits" else "Service": sample(shape.value, key, ancestors, variant)}
    choices = shape.metadata.get("enum")
    if isinstance(choices, list) and choices:
        return choices[0]
    return _scalar(shape, key)


def _scalar(shape: BillingSdkShape, key: str) -> object:
    """Emit typed synthetic scalars without real identity material."""
    if shape.type_name == "string":
        return _text(key)
    if shape.type_name == "timestamp":
        return datetime(2026, 9, 1, 12, tzinfo=UTC)
    if shape.type_name == "boolean":
        return True
    if shape.type_name in {"integer", "long"}:
        minimum = shape.metadata.get("min", 0)
        return max(SAMPLE_COUNT, minimum) if isinstance(minimum, int) else SAMPLE_COUNT
    if shape.type_name in {"double", "float"}:
        return 73.25
    message = "Unsupported synthetic SDK shape"
    raise ValueError(message)


def _text(key: str) -> str:
    """Use realistic provider constants only in their documented synthetic roles."""
    fixed = {
        "Namespace": "AWS/Billing",
        "MetricName": "EstimatedCharges",
        "Amount": "73.25",
        "Unit": "USD",
        "CreationDate": "2026-09-01",
        "LastUpdatedDate": "2026-09-01",
        "LastEvaluatedDate": "2026-09-01",
    }
    if key in fixed:
        return fixed[key]
    if "Arn" in key:
        return "arn:aws:budgets::123456789012:budget/SyntheticBilling"
    return "SyntheticBilling-" + key
