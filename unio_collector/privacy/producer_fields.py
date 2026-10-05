"""Exact classifications for collected provenance producer schemas."""

from __future__ import annotations

import re
from typing import Any

from unio_collector.privacy.registry_entry import PrivacyRegistryEntry

_PERIOD = {
    **dict.fromkeys(("", "raw_input", "kind", "duration_days", "selected_duration", "raw_input.days", "raw_input.months", "raw_input.years"), "safe_metadata"),
    **dict.fromkeys(
        (
            "current_start_date",
            "current_end_date",
            "previous_start_date",
            "previous_end_date",
            "raw_input.date_from",
            "raw_input.date_to",
            "start_date",
            "end_date",
        ),
        "timestamp",
    ),
}
_PERIOD.update({"total_cost": "cost", "currency": "cost"})
_PRICING = {
    "": "safe_metadata",
    "status": "free_text",
    "context_file": "safe_metadata",
    "context_serialized": "safe_metadata",
    "financial_parity_candidate": "cost",
}
_LEDGER = {
    **dict.fromkeys(("", "userIdentity", "responseElements", "responseElements._omitted", "readOnly", "managementEvent", "unio_collector"), "safe_metadata"),
    **dict.fromkeys(("eventVersion", "eventSource", "eventName", "eventType", "errorCode", "userIdentity.type", "userAgent"), "free_text"),
    "eventTime": "timestamp",
    "awsRegion": "region",
    "sourceIPAddress": "free_text",
    "recipientAccountId": "aws_account_id",
    "eventID": "resource_id",
    "requestParameters": "removed_diagnostic",
    "errorMessage": "removed_diagnostic",
    "responseElements.awsRequestId": "removed_diagnostic",
    **dict.fromkeys(("userIdentity.Account", "userIdentity.account_id"), "aws_account_id"),
    **dict.fromkeys(("userIdentity.Arn", "userIdentity.arn"), "arn"),
    **dict.fromkeys(("userIdentity.UserId", "userIdentity.user_id"), "resource_id"),
    **{
        f"unio_collector.{key}": "free_text"
        for key in (
            "scanner_id",
            "collector",
            "operation_safety_status",
            "declared_api_call",
            "error_category",
            "error_reason",
            "service_availability_status",
            "scanner_call_classification",
            "attempt_outcome_reason",
        )
    },
    "unio_collector.attempt_id": "resource_id",
    **{
        f"unio_collector.{key}": "safe_metadata"
        for key in (
            "operation_declared_in_registry",
            "destructive",
            "write_operation",
            "credential_material_returned",
            "local_only_audit_record",
            "authoritative_cloudtrail",
            "aws_cassette_replay",
            "expected_absence",
            "permission_denied",
            "service_unavailable",
            "completed_after_attempt_end",
        )
    },
}
_RATES = {
    "": "sequence",
    "[]": "safe_metadata",
    "[].rate_type": "safe_metadata",
    "[].region": "region",
    "[].resource_variant": "free_text",
    "[].amount": "cost",
    "[].currency": "cost",
    "[].unit": "safe_metadata",
    "[].source": "free_text",
}
_USAGE = {
    "": "sequence",
    "[]": "safe_metadata",
    "[].date": "timestamp",
    "[].service_name": "free_text",
    "[].region": "region",
    "[].usage_type": "free_text",
    "[].cost": "cost",
    "[].currency": "cost",
}
_CONTAINERS = {
    ("scan-result/pricing-context.json", "$.rates[]"),
    ("scan-result/pricing-context.json", "$.usage_records[]"),
    ("account-scope.json", "$.scan_period"),
    ("account-scope.json", "$.scan_period.raw_input"),
    ("analysis-readiness.json", "$.pricing_replay"),
    *(("collection-log.jsonl", path) for path in ("$", "$.userIdentity", "$.responseElements", "$.unio_collector")),
}
_SCHEMAS = {
    ("account-scope.json", "$.scan_period"): _PERIOD,
    ("analysis-readiness.json", "$.pricing_replay"): _PRICING,
    ("collection-log.jsonl", "$"): _LEDGER,
    ("scan-result/pricing-context.json", "$.rates"): _RATES,
    ("scan-result/pricing-context.json", "$.usage_records"): _USAGE,
}


def producer_scope(member: str, path: str) -> bool:
    """Require exact entries within each owned producer subtree."""
    return any(member == name and (path == prefix or path.startswith((prefix + ".", prefix + "["))) for name, prefix in _SCHEMAS)


def producer_category(member: str, path: str) -> str | None:
    """Resolve an exact path; no descendant wildcard is accepted."""
    path = re.sub(r"\[[0-9]+\]", "[]", path)
    for (name, prefix), fields in _SCHEMAS.items():
        if member == name:
            suffix = path[len(prefix) :].removeprefix(".") if path.startswith(prefix) else None
            if suffix is not None and suffix in fields:
                return fields[suffix]
    return None


def producer_entries() -> tuple[PrivacyRegistryEntry, ...]:
    """Register reviewed producer fields and their profile-specific treatment."""
    return tuple(
        PrivacyRegistryEntry(
            domain="protected_bundle_input",
            member_pattern=member,
            json_path_pattern=(prefix + (suffix if suffix.startswith("[") else "." + suffix if suffix else "")).replace("[]", "[*]"),
            value_category=category,
            treatment="remove"
            if category == "removed_diagnostic" or (category == "cost" and profile == "strict")
            else "tokenise"
            if category in {"aws_account_id", "arn", "resource_id", "ipv4"}
            else "generalise"
            if profile == "strict" and category in {"timestamp", "region"}
            else "profile_configurable"
            if category in {"timestamp", "region", "free_text"}
            else "preserve",
            allowed_profiles=(profile,),
            limitations=("Exact producer path; unknown descendants remain blocked and leak scanning is mandatory.",),
        )
        for (member, prefix), fields in _SCHEMAS.items()
        for suffix, category in fields.items()
        for profile in ("standard", "strict", "custom")
    )


def unknown_producer_paths(value: Any, member: str, path: str = "$") -> list[str]:  # noqa: ANN401
    """Check before strict omission, including empty and null unknown fields."""
    category = producer_category(member, path)
    if producer_scope(member, path) and category is None:
        return [member + path[1:]]
    if member == "analysis-readiness.json" and path == "$.pricing_replay.context_file" and value != "scan-result/pricing-context.json":
        return [member + path[1:]]
    if category == "removed_diagnostic":
        return []
    if category == "sequence" and not isinstance(value, list):
        return [member + path[1:]]
    if category not in (None, "sequence") and ((member, path) in _CONTAINERS) != isinstance(value, dict):
        return [member + path[1:]]
    if category not in (None, "sequence") and isinstance(value, list):
        return [member + path[1:]]
    if isinstance(value, dict):
        return [unknown for key, child in value.items() for unknown in unknown_producer_paths(child, member, path + "." + key)]
    if isinstance(value, list):
        return [unknown for child in value for unknown in unknown_producer_paths(child, member, path + "[]")]
    return []


def reduce_strict_pricing_context(payload: dict[str, Any]) -> dict[str, Any]:
    """Keep valid replay metadata while explicitly withdrawing financial inputs."""
    return {
        **payload,
        "status": "redacted",
        "rates": [],
        "usage_records": [],
        "limitations": [*payload.get("limitations", []), "Financial replay inputs were removed by strict privacy protection."],
    }
