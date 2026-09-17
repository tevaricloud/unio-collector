from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.evidence.permission.planning import (
    PermissionDegradationRecord,
    build_degradation_records,
    limitation_category_for_record,
)


def build_permission_degradation_records(
    *,
    bundle: Any,  # noqa: ANN401
    scan_result: Any,  # noqa: ANN401
    collection_records: list[dict[str, Any]],
    scanner_results: list[dict[str, Any]],
) -> tuple[PermissionDegradationRecord, ...]:
    """Build canonical permission-degradation records for bundle output."""
    return build_degradation_records(
        ledger_records=collection_records,
        scanner_results=scanner_results,
        provider_id=str(getattr(scan_result, "provider_id", "aws") or "aws"),
        account_id=str(bundle.account_context.get("account_id") or "unknown-account"),
        run_id=str(bundle.summary.get("run_id") or "") or None,
    )


def build_permission_degradation_payload(
    records: tuple[PermissionDegradationRecord, ...],
) -> dict[str, object]:
    """Return the canonical permission-degradation bundle payload."""
    return {
        "schema_version": "2026-07",
        "records": [record.convert_to_dict() for record in records],
    }


def build_permission_limitation_payload(
    records: tuple[PermissionDegradationRecord, ...],
) -> list[dict[str, object]]:
    """Return the legacy-compatible manifest limitation view."""
    limitations: list[dict[str, object]] = []
    for record in records:
        if record.outcome == "available":
            continue
        limitations.append(
            {
                "type": "permission_degradation",
                "limitation_category": limitation_category_for_record(record),
                "outcome": record.outcome,
                "evidence_interpretation": record.evidence_interpretation,
                "confidence_effect": record.confidence_effect,
                "service": record.api_action.split(":", maxsplit=1)[0],
                "scanner_id": record.scanner_id,
                "region": record.region,
                "reason": record.client_explanation or record.downstream_effect,
                "record_id": record.record_id,
            },
        )
    return limitations


__all__ = [
    "build_permission_degradation_payload",
    "build_permission_degradation_records",
    "build_permission_limitation_payload",
]
