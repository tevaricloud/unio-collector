"""Exact classifications for collected provenance producer schemas."""

from __future__ import annotations

import re
from typing import Any

from unio_collector.collector.bundle.validation.permission_records import permission_record_sort_key
from unio_collector.collector.protocol import DEFAULT_PROTOCOL
from unio_collector.privacy.permission_fields import PERMISSION_CONTAINERS, PERMISSION_SCHEMAS
from unio_collector.privacy.provenance_fields import (
    BILLING_FIELDS,
    DERIVATION_FIELDS,
    LIMITATION_FIELDS,
    PRODUCT_FIELDS,
    SUMMARY_COUNTS,
    SUMMARY_LIMITATIONS,
    valid_summary_count,
)
from unio_collector.privacy.region_scope import REGION_SCOPE_MEMBERS
from unio_collector.privacy.registry_entry import PrivacyRegistryEntry
from unio_collector.privacy.runtime_fields import API_RUNTIME_FIELDS, COLLECTION_RUNTIME_FIELDS, diagnostic_errors

_LEDGER_NAME = DEFAULT_PROTOCOL.namespace

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
    **dict.fromkeys(("", "userIdentity", "responseElements", "responseElements._omitted", "readOnly", "managementEvent", _LEDGER_NAME), "safe_metadata"),
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
        f"{_LEDGER_NAME}.{key}": "free_text"
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
    f"{_LEDGER_NAME}.attempt_id": "resource_id",
    **{
        f"{_LEDGER_NAME}.{key}": "safe_metadata"
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
    *PERMISSION_CONTAINERS,
    ("collection-summary.json", "$.strict_analysis_readiness.pricing_replay"),
    ("collection-summary.json", "$.billing_region_coverage.region_scope_derivation"),
    ("collection-summary.json", "$.limitations[]"),
    *(("collection-summary.json", "$." + field) for field in SUMMARY_COUNTS),
    ("collection-summary.json", "$.billing_region_scope_derivation"),
    ("manifest.json", "$.product_execution"),
    ("manifest.json", "$.product_execution.period_policy"),
    ("collection-summary.json", "$.billing_region_coverage"),
    ("collection-summary.json", "$.billing_region_coverage.current_period"),
    ("collection-summary.json", "$.billing_region_coverage.region_costs[]"),
    ("collection-summary.json", "$.stable_limitation_details[]"),
    ("scan-result/api-runtime-summary.json", "$"),
    ("scan-result/api-runtime-summary.json", "$.records[]"),
    ("scan-result/api-runtime-summary.json", "$.totals"),
    ("collection-summary.json", "$.collection_runtime_summary"),
    ("collection-summary.json", "$.collection_runtime_summary.slowest_tasks[]"),
    ("collection-summary.json", "$.api_runtime_summary"),
    ("collection-summary.json", "$.api_runtime_summary.records[]"),
    ("collection-summary.json", "$.api_runtime_summary.totals"),
    ("scan-result/pricing-context.json", "$.rates[]"),
    ("scan-result/pricing-context.json", "$.usage_records[]"),
    ("scan-result/report-bundle.json", "$.scan_period"),
    ("scan-result/report-bundle.json", "$.scan_period.raw_input"),
    ("account-scope.json", "$.scan_period"),
    ("account-scope.json", "$.scan_period.raw_input"),
    ("analysis-readiness.json", "$.pricing_replay"),
    *(("collection-log.jsonl", path) for path in ("$", "$.userIdentity", "$.responseElements", f"$.{_LEDGER_NAME}")),
}
_SCHEMAS = {
    **PERMISSION_SCHEMAS,
    ("collection-summary.json", "$.strict_analysis_readiness.pricing_replay"): _PRICING,
    ("collection-summary.json", "$.limitations"): SUMMARY_LIMITATIONS,
    **{("collection-summary.json", "$." + field): {"": "safe_metadata", **dict.fromkeys(keys, "summary_count")} for field, keys in SUMMARY_COUNTS.items()},
    ("collection-summary.json", "$.billing_region_scope_derivation"): DERIVATION_FIELDS,
    ("manifest.json", "$.product_execution"): PRODUCT_FIELDS,
    ("collection-summary.json", "$.billing_region_coverage"): BILLING_FIELDS,
    ("collection-summary.json", "$.stable_limitation_details"): {
        "": "sequence",
        **{"[]" + ("." + key if key else ""): value for key, value in LIMITATION_FIELDS.items()},
    },
    ("scan-result/api-runtime-summary.json", "$"): API_RUNTIME_FIELDS,
    ("collection-summary.json", "$.collection_runtime_summary"): COLLECTION_RUNTIME_FIELDS,
    ("collection-summary.json", "$.api_runtime_summary"): API_RUNTIME_FIELDS,
    ("scan-result/report-bundle.json", "$.scan_period"): _PERIOD,
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
        if member == name and (path == prefix or path.startswith((prefix + ".", prefix + "["))):
            suffix = path[len(prefix) :].removeprefix(".")
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
            if category in {"removed_diagnostic", "diagnostic_counts", "diagnostic_groups"} or (category == "cost" and profile == "strict")
            else "tokenise"
            if category in {"aws_account_id", "arn", "resource_id", "resource_name", "ipv4"}
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
    if (member, path) in {
        ("analysis-readiness.json", "$.pricing_replay.context_file"),
        ("collection-summary.json", "$.strict_analysis_readiness.pricing_replay.context_file"),
    } and value != "scan-result/pricing-context.json":
        return [member + path[1:]]
    diagnostics = _value_errors(category, value, member, path)
    if diagnostics is not None:
        return diagnostics
    if category == "removed_diagnostic":
        return []
    if category == "sequence" and not isinstance(value, list):
        return [member + path[1:]]
    if category not in (None, "sequence") and ((member, path) in _CONTAINERS) != isinstance(value, dict):
        return [member + path[1:]]
    if category not in (None, "sequence") and isinstance(value, list):
        return [member + path[1:]]
    if isinstance(value, dict):
        return _unknown_dictionary_paths(value, member, path)
    if isinstance(value, list):
        return [unknown for child in value for unknown in unknown_producer_paths(child, member, path + "[]")]
    return []


def _unknown_dictionary_paths(value: dict[str, Any], member: str, path: str) -> list[str]:
    """Reject path syntax only at explicitly owned producer boundaries."""
    failures: list[str] = []
    for key, child in value.items():
        child_path = path + "." + key
        if any(character in key for character in ".[]") and (_owned_producer_path(member, path) or _owned_producer_path(member, child_path)):
            failures.append(member + child_path[1:])
        else:
            failures.extend(unknown_producer_paths(child, member, child_path))
    return failures


def _owned_producer_path(member: str, path: str) -> bool:
    """Include exact region-scope ownership without extending its admitted schema."""
    return producer_scope(member, path) or (
        member in REGION_SCOPE_MEMBERS and (path == "$.region_scope" or path.startswith(("$.region_scope.", "$.region_scope[")))
    )


def reduce_strict_pricing_context(payload: dict[str, Any]) -> dict[str, Any]:
    """Keep valid replay metadata while explicitly withdrawing financial inputs."""
    return {
        **payload,
        "status": "redacted",
        "rates": [],
        "usage_records": [],
        "limitations": [*payload.get("limitations", []), "Financial replay inputs were removed by strict privacy protection."],
    }


def _value_errors(category: str | None, value: Any, member: str, path: str) -> list[str] | None:  # noqa: ANN401
    """Validate finite summary counters before applying any profile treatment."""
    if category == "summary_count":
        return [] if valid_summary_count(value) else [member + path[1:]]
    return diagnostic_errors(category, value, member, path)


def normalise_producer_payload(name: str, payload: dict[str, Any], profile_id: str) -> dict[str, Any]:
    """Keep producer ordering valid and replace strict financial payloads."""
    if name == "permissions/degradation-records.json":
        payload["records"].sort(key=permission_record_sort_key)
    if profile_id == "strict":
        if name == "scan-result/pricing-context.json":
            return reduce_strict_pricing_context(payload)
        if name == "analysis-readiness.json" and isinstance(payload.get("pricing_replay"), dict):
            payload["pricing_replay"]["status"] = "redacted"
    return payload
