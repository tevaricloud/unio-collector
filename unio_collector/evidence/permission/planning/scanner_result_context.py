from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.scanners.registry.catalog import get_scanner


def actions_for_scanner_result(result: dict[str, Any]) -> tuple[str, ...]:
    """Return the best available declared or attempted action set."""
    for field_name in (
        "required_iam_actions",
        "api_calls_attempted",
        "aws_api_calls",
        "conditional_iam_actions",
    ):
        values = result.get(field_name)
        if isinstance(values, list | tuple) and values:
            return tuple(sorted({str(value) for value in values if str(value)}))
    return ("unknown:unknown",)


def iam_action_requirement_for_scanner_action(
    result: dict[str, Any],
    action: str,
) -> str:
    """Return required versus conditional from scanner-result metadata."""
    conditional_actions = {str(value) for value in result.get("conditional_iam_actions", []) or []}
    required_actions = {str(value) for value in result.get("required_iam_actions", []) or []}
    if action in conditional_actions and action not in required_actions:
        return "conditional"
    return "required"


def exact_requirement_type_for_action(
    scanner_id: str,
    action: str,
) -> str | None:
    """Return a requirement type only when registry metadata is unambiguous."""
    try:
        definition = get_scanner(scanner_id)
    except ValueError:
        return None
    values = {item.requirement_type for item in definition.iam_requirements or () if item.api_action == action}
    return values.pop() if len(values) == 1 else None


def region_for_scanner_result(result: dict[str, Any]) -> str:
    """Return the first recorded scan region or the AWS-global marker."""
    regions = result.get("regions_scanned")
    if isinstance(regions, list | tuple) and regions:
        return str(regions[0] or "aws-global")
    return "aws-global"


def evidence_category_for_scanner(scanner_id: str, action: str) -> str:
    """Return the most specific registry evidence category available."""
    try:
        definition = get_scanner(scanner_id)
    except ValueError:
        return action.split(":", maxsplit=1)[0] if ":" in action else "unknown"
    if definition.resource_types:
        return definition.resource_types[0]
    if definition.aws_services:
        return definition.aws_services[0]
    return action.split(":", maxsplit=1)[0] if ":" in action else "unknown"


__all__ = [
    "actions_for_scanner_result",
    "evidence_category_for_scanner",
    "exact_requirement_type_for_action",
    "iam_action_requirement_for_scanner_action",
    "region_for_scanner_result",
]
