from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws import errors as aws_errors

LEGACY_TYPE_OUTCOMES = {
    "access_denied": "denied",
    "permission_denied": "denied",
    "expected_absence": "expected_absence",
    "not_configured": "expected_absence",
    "not_found": "expected_absence",
    "service_not_enabled": "service_unavailable",
    "service_unavailable": "service_unavailable",
    "region_unsupported": "unsupported_region",
    "unsupported_region": "unsupported_region",
    "unsupported_operation": "unsupported_operation",
    "dependency_unavailable": "dependency_unavailable",
    "endpoint_unavailable": "dependency_unavailable",
    "chargeable_api_disabled": "chargeable_disabled",
    "chargeable_disabled": "chargeable_disabled",
    "failed": "interrupted",
    "interrupted": "interrupted",
    "scanner_failed": "interrupted",
    "partial": "partial",
    "partial_collection": "partial",
}

LEGACY_OUTCOME_MAP = {
    "permission_denied": "denied",
    "denied": "denied",
    "expected_absence": "expected_absence",
    "service_not_enabled": "service_unavailable",
    "service_unavailable": "service_unavailable",
    "unsupported_region": "unsupported_region",
    "unsupported_operation": "unsupported_operation",
    "endpoint_unavailable": "dependency_unavailable",
    "dependency_unavailable": "dependency_unavailable",
    "chargeable_api_disabled": "chargeable_disabled",
    "chargeable_disabled": "chargeable_disabled",
    "scanner_failed": "interrupted",
    "failed": "interrupted",
    "interrupted": "interrupted",
    "partial": "partial",
    "unknown": "unknown",
}

REASON_OUTCOME_MARKERS = (
    (("not configured", "not found", "no such"), "expected_absence"),
    (("not enabled", "not subscribed"), "service_unavailable"),
    (("unsupported region", "not opted"), "unsupported_region"),
    (("unsupported operation",), "unsupported_operation"),
    (("endpoint unavailable",), "dependency_unavailable"),
    (("chargeable", "disabled"), "chargeable_disabled"),
    (("partial",), "partial"),
)


def classify_legacy_limitation_outcome(limitation: dict[str, Any]) -> str:
    """Map legacy limitation payloads into canonical degradation outcomes."""
    limitation_type = str(limitation.get("type") or "").casefold()
    outcome = str(limitation.get("outcome") or "").casefold()
    if outcome:
        return normalize_legacy_outcome(outcome)
    if limitation_type in LEGACY_TYPE_OUTCOMES:
        return LEGACY_TYPE_OUTCOMES[limitation_type]
    if aws_errors.is_expected_absence_error_code(str(limitation.get("error_code") or "")):
        return "expected_absence"
    reason = _legacy_reason(limitation)
    for markers, mapped_outcome in REASON_OUTCOME_MARKERS:
        if all(marker in reason for marker in markers):
            return mapped_outcome
    return "unknown"


def normalize_legacy_outcome(outcome: str) -> str:
    """Normalize legacy outcome labels to canonical degradation outcomes."""
    return LEGACY_OUTCOME_MAP.get(outcome, "unknown")


def _legacy_reason(limitation: dict[str, Any]) -> str:
    return " ".join(str(limitation.get(field) or "") for field in ("reason", "error_code", "error_message", "status")).casefold()


__all__ = ["classify_legacy_limitation_outcome", "normalize_legacy_outcome"]
