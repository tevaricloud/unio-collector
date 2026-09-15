"""Collector-safe audit-cost scanner evidence signal builders."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Any, cast

from unio_collector.aws.audit_cost.waf.record import (
    WafCostGovernanceRecord,
)


def has_audit_cost_context(record: object) -> bool:
    """Return whether audit-service metadata has billing context attached."""
    return (
        getattr(record, "service_current_cost", None) is not None
        or getattr(record, "regional_current_cost", None) is not None
        or int(getattr(record, "regional_cost_record_count", 0) or 0) > 0
    )


def build_audit_cost_context_source_signal(record: object) -> dict[str, object]:
    """Return collector-safe billing-context source signal fields."""
    return {
        "service_current_cost": _string_or_none(getattr(record, "service_current_cost", None)),
        "service_previous_cost": _string_or_none(getattr(record, "service_previous_cost", None)),
        "service_cost_currency": getattr(record, "service_cost_currency", None),
        "regional_current_cost": _string_or_none(getattr(record, "regional_current_cost", None)),
        "regional_cost_currency": getattr(record, "regional_cost_currency", None),
        "regional_cost_record_count": getattr(record, "regional_cost_record_count", 0),
        "cost_context_source": ("AWS Cost Explorer" if has_audit_cost_context(record) else None),
        "cost_context_scope": ("service_and_region_billing_signal" if has_audit_cost_context(record) else None),
    }


def build_audit_cost_context_missing_signals(record: object) -> list[str]:
    """Return collector-safe billing-context limitations."""
    if not has_audit_cost_context(record):
        return []
    return [
        "Cost Explorer context is service or region-level billing evidence and does not attribute spend to individual audit-service resources or controls.",
    ]


def build_permission_missing_signals(permission_errors: list[str]) -> list[str]:
    """Return collector-safe permission limitations."""
    if not permission_errors:
        return []
    summarized_errors = summarize_permission_errors(permission_errors)
    return [
        f"Some supporting audit-service metadata could not be collected: {', '.join(summarized_errors)}.",
    ]


def summarize_permission_errors(permission_errors: list[str]) -> list[str]:
    """Summarise repeated permission errors without analyzer dependencies."""
    counts = Counter(permission_errors)
    summaries: list[str] = []
    for error, count in sorted(counts.items())[:5]:
        if count == 1:
            summaries.append(error)
            continue
        summaries.append(f"{error} ({count} occurrences)")
    omitted_count = max(len(counts) - len(summaries), 0)
    if omitted_count:
        summaries.append(f"{omitted_count} additional error type(s)")
    return summaries


def build_waf_collection_missing_signals(record: object) -> list[str]:
    """Return WAF collection limitations without importing analyzer modules."""
    if not isinstance(record, WafCostGovernanceRecord):
        return []
    if record.association_metadata_collected:
        return []
    return [
        (
            "WAF web ACL association metadata was not collected because "
            "association_detail_mode was summary; association-status findings "
            "were suppressed for this scan."
        ),
    ]


def build_audit_cost_evidence_signal(scanner_id: str, record: object) -> dict[str, Any]:
    """Return the scanner-evidence metric signal for audit-cost records."""
    signal = dict(asdict(cast("Any", record))) if hasattr(record, "__dataclass_fields__") else dict(getattr(record, "__dict__", {}))
    signal["signal_type"] = f"{scanner_id.replace('-', '_')}_metadata"
    signal.update(build_audit_cost_context_source_signal(record))
    return signal


def _string_or_none(value: object) -> str | None:
    if value is None:
        return None
    return str(value)
