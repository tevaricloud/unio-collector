from __future__ import annotations  # noqa: D100

REQUIRED_PERMISSION_DENIED = "required_permission_denied"
OPTIONAL_ENRICHMENT_PERMISSION_DENIED = "optional_enrichment_permission_denied"
EVIDENCE_UNAVAILABLE = "evidence_unavailable"
EVIDENCE_UNSUPPORTED = "evidence_unsupported"
SCANNER_EXECUTION_DEGRADED = "scanner_execution_degraded"

STABLE_LIMITATION_CATEGORIES = (
    REQUIRED_PERMISSION_DENIED,
    OPTIONAL_ENRICHMENT_PERMISSION_DENIED,
    EVIDENCE_UNAVAILABLE,
    EVIDENCE_UNSUPPORTED,
    SCANNER_EXECUTION_DEGRADED,
)


def limitation_category_for_record(record: object) -> str:  # noqa: D103
    explicit = _record_value(record, "limitation_category")
    if explicit in STABLE_LIMITATION_CATEGORIES:
        return explicit
    return limitation_category_for_values(
        outcome=_record_value(record, "outcome") or "unknown",
        iam_action_requirement=_record_value(record, "iam_action_requirement"),
    )


def limitation_category_for_values(  # noqa: D103
    *,
    outcome: str,
    iam_action_requirement: str | None = None,
) -> str:
    if outcome in {"available", "expected_absence"}:
        return ""
    if outcome == "denied":
        if str(iam_action_requirement or "").casefold() == "conditional":
            return OPTIONAL_ENRICHMENT_PERMISSION_DENIED
        return REQUIRED_PERMISSION_DENIED
    if outcome in {
        "chargeable_disabled",
        "dependency_unavailable",
        "not_exercised",
        "service_unavailable",
    }:
        return EVIDENCE_UNAVAILABLE
    if outcome in {"unsupported_operation", "unsupported_region"}:
        return EVIDENCE_UNSUPPORTED
    if outcome in {
        "inferred",
        "interrupted",
        "partial",
        "stale",
        "throttled",
        "unknown",
    }:
        return SCANNER_EXECUTION_DEGRADED
    return SCANNER_EXECUTION_DEGRADED


def stable_limitation_detail(  # noqa: D103
    record: object,
    stable_category: str,
) -> dict[str, object]:
    api_action = _record_value(record, "api_action")
    return {
        "category": stable_category,
        "record_id": _record_value(record, "record_id"),
        "scanner_id": _record_value(record, "scanner_id"),
        "service": api_action.split(":", maxsplit=1)[0] if api_action else "",
        "api_action": api_action,
        "account_id": _record_value(record, "account_id"),
        "region": _record_value(record, "region"),
        "outcome": _record_value(record, "outcome"),
        "iam_action_requirement": _record_value(record, "iam_action_requirement"),
        "requirement_type": _record_value(record, "requirement_type"),
        "resource_type": _record_value(record, "resource_type"),
        "resource_id": _record_value(record, "resource_id"),
        "safe_scope": _record_value(record, "safe_scope"),
        "evidence_categories": _record_strings(record, "evidence_categories"),
        "affected_fields": _record_strings(record, "affected_fields"),
        "requested_account_id": _record_value(record, "requested_account_id"),
        "requested_region": _record_value(record, "requested_region"),
        "scanner_continued": _record_bool(record, "scanner_continued"),
        "collection_continued": _record_bool(record, "collection_continued"),
        "related_findings_may_be_incomplete": _record_bool(
            record,
            "related_findings_may_be_incomplete",
        ),
        "evidence_interpretation": _record_value(
            record,
            "evidence_interpretation",
        ),
        "confidence_effect": _record_value(record, "confidence_effect"),
        "remediation_permission": _record_value(
            record,
            "remediation_permission",
        ),
        "client_explanation": _record_value(record, "client_explanation"),
    }


def _record_value(record: object, field: str) -> str:
    if isinstance(record, dict):
        return str(record.get(field) or "")
    return str(getattr(record, field, "") or "")


def _record_bool(record: object, field: str) -> bool | None:
    value = record.get(field) if isinstance(record, dict) else getattr(record, field, None)
    return value if isinstance(value, bool) else None


def _record_strings(record: object, field: str) -> list[str]:
    value = record.get(field) if isinstance(record, dict) else getattr(record, field, ())
    if not isinstance(value, list | tuple):
        return []
    return sorted(str(item) for item in value if str(item))


__all__ = [
    "EVIDENCE_UNAVAILABLE",
    "EVIDENCE_UNSUPPORTED",
    "OPTIONAL_ENRICHMENT_PERMISSION_DENIED",
    "REQUIRED_PERMISSION_DENIED",
    "SCANNER_EXECUTION_DEGRADED",
    "STABLE_LIMITATION_CATEGORIES",
    "limitation_category_for_record",
    "limitation_category_for_values",
    "stable_limitation_detail",
]
