"""Canonical permission-degradation summary statistics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.evidence.permission.planning.limitation_category import (
    limitation_category_for_record,
    stable_limitation_detail,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from unio_collector.evidence.permission.planning.degradation import (
        PermissionDegradationRecord,
    )

LIMITATION_CATEGORY_BY_OUTCOME = {
    "chargeable_disabled": "chargeable_api_disabled",
    "denied": "permission_denied",
    "dependency_unavailable": "endpoint_unavailable",
    "expected_absence": "expected_absence",
    "inferred": "inferred",
    "interrupted": "scanner_failed",
    "not_exercised": "unknown",
    "partial": "partial",
    "service_unavailable": "service_not_enabled",
    "stale": "stale",
    "throttled": "partial",
    "unknown": "unknown",
    "unsupported_operation": "unsupported_operation",
    "unsupported_region": "unsupported_region",
}


def summarize_degradation_records(
    records: Sequence[PermissionDegradationRecord | dict[str, Any]],
) -> dict[str, Any]:
    """Return deterministic aggregate counts for canonical degradation records."""
    outcomes: dict[str, int] = {}
    limitation_counts: dict[str, int] = {}
    stable_limitation_counts: dict[str, int] = {}
    secondary_classification_counts: dict[str, int] = {}
    confidence_effects: dict[str, int] = {}
    evidence_interpretations: dict[str, int] = {}
    stable_limitation_details: list[dict[str, object]] = []
    degradation_details: list[dict[str, object]] = []
    affected_scanner_ids: set[str] = set()
    affected_services: set[str] = set()
    limitation_count = 0
    for record in records:
        outcome = _record_value(record, "outcome") or "unknown"
        _increment(outcomes, outcome)
        _increment(
            confidence_effects,
            _record_value(record, "confidence_effect") or "unknown",
        )
        _increment(
            evidence_interpretations,
            _record_value(record, "evidence_interpretation") or "unknown",
        )
        if outcome == "available":
            continue
        limitation_count += 1
        _increment(
            limitation_counts,
            LIMITATION_CATEGORY_BY_OUTCOME.get(outcome, "unknown"),
        )
        stable_category = limitation_category_for_record(record)
        degradation_details.append(
            stable_limitation_detail(
                record,
                stable_category or LIMITATION_CATEGORY_BY_OUTCOME.get(outcome, "unknown"),
            ),
        )
        if stable_category:
            _increment(stable_limitation_counts, stable_category)
            stable_limitation_details.append(
                stable_limitation_detail(record, stable_category),
            )
        classification = _record_value(record, "error_classification")
        if classification and classification != "none":
            _increment(secondary_classification_counts, classification)
        scanner_id = _record_value(record, "scanner_id")
        if scanner_id:
            affected_scanner_ids.add(scanner_id)
        api_action = _record_value(record, "api_action")
        if api_action:
            affected_services.add(api_action.split(":", maxsplit=1)[0])
    return {
        "record_count": len(records),
        "limitation_count": limitation_count,
        "limitation_counts": limitation_counts,
        "stable_limitation_counts": stable_limitation_counts,
        "stable_limitation_details": sorted(
            stable_limitation_details,
            key=lambda item: (
                str(item.get("category") or ""),
                str(item.get("scanner_id") or ""),
                str(item.get("service") or ""),
                str(item.get("account_id") or ""),
                str(item.get("region") or ""),
                str(item.get("record_id") or ""),
            ),
        ),
        "degradation_details": sorted(
            degradation_details,
            key=lambda item: (
                str(item.get("category") or ""),
                str(item.get("scanner_id") or ""),
                str(item.get("api_action") or ""),
                str(item.get("region") or ""),
                str(item.get("record_id") or ""),
            ),
        ),
        "secondary_classification_counts": secondary_classification_counts,
        "outcomes": outcomes,
        "confidence_effects": confidence_effects,
        "evidence_interpretations": evidence_interpretations,
        "affected_scanner_ids": sorted(affected_scanner_ids),
        "affected_services": sorted(affected_services),
    }


def _record_value(
    record: PermissionDegradationRecord | dict[str, Any],
    field: str,
) -> str:
    if isinstance(record, dict):
        return str(record.get(field) or "")
    return str(getattr(record, field) or "")


def _increment(counter: dict[str, int], value: str) -> None:
    counter[value] = counter.get(value, 0) + 1


__all__ = ["summarize_degradation_records"]
