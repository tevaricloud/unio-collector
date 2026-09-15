"""Preserve bundle minimisation metadata independently of finding selection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.collector.minimisation import EvidenceMinimisationOptions


def build_minimised_summary(
    source: dict[str, Any],
    minimisation: EvidenceMinimisationOptions,
    *,
    removed_count: int,
    retained_count: int,
) -> dict[str, Any]:
    """Copy summary metadata using supplied counts and explicit export options."""
    summary = dict(source)
    if minimisation.no_cost_data:
        summary.pop("last_completed_month_billing_baseline", None)
        summary.pop("known_savings_spend_percentage", None)
        summary["billing_baseline_status"] = "not_collected"
        summary["billing_baseline_limitations"] = [
            "Completed-month billing evidence was omitted by the no-cost-data export policy.",
        ]
    summary["collector_minimisation_pruned_findings"] = {
        "removed_count": removed_count,
        "retained_count": retained_count,
        "excluded_services": list(minimisation.exclude_services),
        "no_cost_data": minimisation.no_cost_data,
    }
    return summary
