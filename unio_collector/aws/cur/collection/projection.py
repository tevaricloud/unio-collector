"""Serialize the existing compact billing aggregates without finding semantics."""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cur.summary import calculate_percentage, decimal_mapping_to_records

if TYPE_CHECKING:
    from unio_collector.aws.cur.collection.result import CurBillingResult


def project_billing_evidence(result: CurBillingResult, *, paths_supplied: bool) -> dict[str, Any]:
    """Preserve the historical 25-record projections and exact aggregate scalars."""
    reasons = list(result.reason_codes)
    if result.rows_skipped:
        reasons.append("unreadable_billing_rows")
    status = "partial" if reasons or result.rows_skipped else "complete"
    if not result.rows_read:
        status = "unavailable"
    return {
        "source_files": list(result.source_files),
        "rows_read": result.rows_read,
        "rows_matched": result.rows_matched,
        "rows_skipped": result.rows_skipped,
        "currency": result.currency,
        "total_cost": str(result.total_cost),
        "top_services": decimal_mapping_to_records(result.service_costs, "service"),
        "top_regions": decimal_mapping_to_records(result.region_costs, "region"),
        "top_usage_types": decimal_mapping_to_records(result.usage_type_costs, "usage_type"),
        "top_resources": result.top_resources,
        "tag_groups": [
            {"group_key": key, "group_value": value, "estimated_cost": str(cost.quantize(Decimal("0.01")))}
            for (key, value), cost in sorted(result.tag_costs.items(), key=lambda item: item[1], reverse=True)
        ],
        "unassigned_cost": str(result.unassigned_cost),
        "assigned_cost": str((result.total_cost - result.unassigned_cost).quantize(Decimal("0.01"))),
        "tag_assignment_percentage": calculate_percentage(result.total_cost - result.unassigned_cost, result.total_cost),
        "limitations": list(result.limitations),
        "paths_supplied": paths_supplied,
        "collection_status": status,
        "collection_issues": [{"error_code": code} for code in dict.fromkeys(reasons)],
        "aggregate_counts": {
            "services": len(result.service_costs),
            "regions": len(result.region_costs),
            "usage_types": len(result.usage_type_costs),
            "resources": len(result.resource_costs),
            "tag_groups": len(result.tag_costs),
        },
    }
