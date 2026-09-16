"""Neutral quota collection envelope and completeness counters."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.scanners.service_quota.supported_checks import SUPPORTED_SERVICE_QUOTA_CHECKS

if TYPE_CHECKING:
    from unio_collector.scanners.service_quota.observation import ServiceQuotaObservation


def build_quota_collection_payload(
    *,
    account_id: str,
    period: dict[str, Any],
    selected_regions: list[str],
    threshold: int | None,
    records: list[ServiceQuotaObservation],
    warnings: list[str],
    limitations: list[str],
) -> dict[str, Any]:
    """Keep configured input opaque while recording read completeness."""
    unavailable_count = sum(1 for record in records if not record.quota_found or record.quota_value is None or record.current_usage is None)
    return {
        "collection_evidence_version": 1,
        "account_id": account_id,
        "period": dict(period),
        "selected_regions": list(selected_regions),
        "threshold": threshold,
        "status": "completed_with_warnings" if warnings or unavailable_count else "completed",
        "supported_check_count": len(SUPPORTED_SERVICE_QUOTA_CHECKS),
        "attempted_record_count": len(records),
        "expected_record_count": len(selected_regions) * len(SUPPORTED_SERVICE_QUOTA_CHECKS),
        "unavailable_record_count": unavailable_count,
        "quota_records": [record.convert_to_dict() for record in records],
        "warnings": list(warnings),
        "limitations": list(limitations),
    }
