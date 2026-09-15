from __future__ import annotations  # noqa: D100


def evidence_interpretation_for_outcome(outcome: str) -> str:  # noqa: D103
    return {
        "available": "present",
        "denied": "absent_due_to_denial",
        "chargeable_disabled": "absent_due_to_chargeable_disabled",
        "expected_absence": "observed_absent",
        "not_exercised": "absent_not_collected",
        "partial": "partial",
        "interrupted": "partial",
        "service_unavailable": "absent_not_collected",
        "unsupported_operation": "absent_not_collected",
        "unsupported_region": "absent_not_collected",
        "throttled": "partial",
        "dependency_unavailable": "absent_not_collected",
        "stale": "stale",
        "inferred": "inferred",
        "unknown": "unknown",
    }.get(outcome, "unknown")


def confidence_effect_for_outcome(outcome: str) -> str:  # noqa: D103
    if outcome == "available":
        return "none"
    if outcome == "expected_absence":
        return "none"
    if outcome in {
        "denied",
        "service_unavailable",
        "unsupported_region",
        "chargeable_disabled",
        "dependency_unavailable",
        "unsupported_operation",
        "not_exercised",
        "stale",
    }:
        return "reduce"
    if outcome in {"partial", "interrupted", "throttled", "inferred"}:
        return "qualify"
    return "unknown"


def downstream_effect_for_outcome(outcome: str) -> str:  # noqa: D103
    if outcome == "available":
        return "Evidence was available for downstream analysis."
    if outcome == "expected_absence":
        return "AWS authoritatively reported that the optional resource or configuration was absent; downstream analysis may evaluate that absence."
    return "Downstream analysis must not treat missing evidence as complete coverage."


__all__ = [
    "confidence_effect_for_outcome",
    "downstream_effect_for_outcome",
    "evidence_interpretation_for_outcome",
]
