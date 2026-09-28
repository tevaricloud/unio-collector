"""Environment-aware privacy transformations for structured records."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.environment.projection import build_environment_context

if TYPE_CHECKING:
    from unio_collector.environment import EnvironmentClassifier
    from unio_collector.privacy.registry import ClassificationSummary


def apply_environment_context(
    source: dict[str, Any],
    transformed: dict[str, Any],
    *,
    classifier: EnvironmentClassifier,
    semantics: str,
    summary: ClassificationSummary,
) -> dict[str, Any]:
    """Add only the configured privacy-safe canonical environment context."""
    context = build_environment_context(
        source,
        classifier=classifier,
        semantics=semantics,  # type: ignore[arg-type]
    )
    if context is not None:
        transformed["environment_context"] = context
        summary.preserved += len(context)
    return transformed


def remove_internal_ledger_diagnostics(value: dict[str, Any]) -> dict[str, Any]:
    """Remove collection-ledger fields that must not cross the privacy boundary."""
    sanitized = dict(value)
    sanitized.pop("errorMessage", None)
    sanitized.pop("requestParameters", None)
    response = sanitized.get("responseElements")
    if isinstance(response, dict) and "awsRequestId" in response:
        sanitized_response = dict(response)
        sanitized_response.pop("awsRequestId", None)
        sanitized["responseElements"] = sanitized_response
    return sanitized


def display_path(member_path: str, json_path: str) -> str:
    """Render a bundle member and JSON path for privacy diagnostics."""
    return member_path if json_path == "$" else f"{member_path}{json_path[1:]}"
