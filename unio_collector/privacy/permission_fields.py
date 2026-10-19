"""Exact permission-summary and degradation producer privacy contracts."""

from __future__ import annotations

from unio_collector.privacy.provenance_fields import LIMITATION_FIELDS, SUMMARY_COUNTS

PERMISSION_COUNTS = {
    **SUMMARY_COUNTS,
    "outcomes": (
        "available",
        "chargeable_disabled",
        "denied",
        "dependency_unavailable",
        "expected_absence",
        "inferred",
        "interrupted",
        "not_exercised",
        "partial",
        "service_unavailable",
        "stale",
        "throttled",
        "unknown",
        "unsupported_operation",
        "unsupported_region",
    ),
    "confidence_effects": ("none", "reduce", "qualify", "unknown"),
    "evidence_interpretations": (
        "present",
        "absent_due_to_denial",
        "absent_due_to_chargeable_disabled",
        "observed_absent",
        "absent_not_collected",
        "partial",
        "stale",
        "inferred",
        "unknown",
    ),
}

_ACTION_LISTS = (
    "required_iam_actions",
    "conditional_iam_actions",
    "available_actions",
    "available_conditional_actions",
    "missing_actions",
    "missing_conditional_actions",
    "service_unavailable_actions",
    "service_unavailable_conditional_actions",
    "not_attempted_actions",
    "not_attempted_conditional_actions",
    "unknown_actions",
    "unknown_conditional_actions",
)
_SCANNER = {
    "": "safe_metadata",
    **dict.fromkeys(("scanner_id", "required_permission_level", "scanner_status"), "free_text"),
    **dict.fromkeys(_ACTION_LISTS, "sequence"),
    **{key + "[]": "free_text" for key in _ACTION_LISTS},
}
_DETAIL = {"": "sequence", **{"[]" + ("." + key if key else ""): category for key, category in LIMITATION_FIELDS.items()}}
_DEGRADATION = {
    "": "safe_metadata",
    "record_count": "summary_count",
    "limitation_count": "summary_count",
    **dict.fromkeys(PERMISSION_COUNTS, "safe_metadata"),
    **{key + "." + item: "summary_count" for key, items in PERMISSION_COUNTS.items() for item in items},
    **{key + suffix: category for key in ("stable_limitation_details", "degradation_details") for suffix, category in _DETAIL.items()},
    **dict.fromkeys(("affected_scanner_ids", "affected_services"), "sequence"),
    **dict.fromkeys(("affected_scanner_ids[]", "affected_services[]"), "free_text"),
}
_RECORD = {
    "": "safe_metadata",
    **dict.fromkeys(
        (
            "schema_version",
            "provider_id",
            "scanner_id",
            "api_action",
            "evidence_category",
            "outcome",
            "error_code",
            "error_classification",
            "evidence_interpretation",
            "confidence_effect",
            "downstream_effect",
            "client_explanation",
            "iam_action_requirement",
            "limitation_category",
            "requirement_type",
            "resource_type",
            "safe_scope",
            "remediation_permission",
        ),
        "free_text",
    ),
    **dict.fromkeys(("record_id", "run_id", "ledger_event_id", "resource_id"), "resource_id"),
    **dict.fromkeys(("account_id", "requested_account_id"), "aws_account_id"),
    **dict.fromkeys(("region", "requested_region"), "region"),
    **dict.fromkeys(("collection_continued", "api_call_succeeded", "scanner_continued", "related_findings_may_be_incomplete"), "safe_metadata"),
    "timestamp": "timestamp",
    "technical_detail": "removed_diagnostic",
    **dict.fromkeys(("evidence_categories", "affected_fields"), "sequence"),
    **dict.fromkeys(("evidence_categories[]", "affected_fields[]"), "free_text"),
}
_FAILURE = {
    "": "safe_metadata",
    "region": "region",
    "error_message": "removed_diagnostic",
    **dict.fromkeys(("scanner_id", "event_source", "event_name", "error_code"), "free_text"),
}

PERMISSION_SCHEMAS = {
    ("manifest.json", "$.permission_limitations"): {
        "": "sequence",
        "[]": "safe_metadata",
        "[].record_id": "resource_id",
        "[].region": "region",
        **{
            "[]." + key: "free_text"
            for key in (
                "type",
                "permission",
                "service",
                "reason",
                "limitation_category",
                "outcome",
                "evidence_interpretation",
                "confidence_effect",
                "scanner_id",
            )
        },
    },
    ("permissions-summary.json", "$.permission_degradation"): _DEGRADATION,
    ("permissions-summary.json", "$.scanner_permissions"): {"": "sequence", **{"[]" + ("." + key if key else ""): value for key, value in _SCANNER.items()}},
    ("permissions-summary.json", "$.permission_failures"): {"": "sequence", **{"[]" + ("." + key if key else ""): value for key, value in _FAILURE.items()}},
    ("permissions/degradation-records.json", "$"): {
        "": "safe_metadata",
        "schema_version": "free_text",
        "records": "sequence",
        **{"records[]" + ("." + key if key else ""): value for key, value in _RECORD.items()},
    },
    **{
        ("permissions-summary.json", "$." + key): {"": "sequence", "[]": "free_text"}
        for key in (
            "available_actions",
            "missing_actions",
            "service_unavailable_actions",
            "not_attempted_actions",
            "not_attempted_conditional_actions",
            "unknown_actions",
            "write_actions_observed",
        )
    },
}
PERMISSION_CONTAINERS = {
    ("manifest.json", "$.permission_limitations[]"),
    ("permissions/degradation-records.json", "$"),
    ("permissions/degradation-records.json", "$.records[]"),
    ("permissions-summary.json", "$.permission_degradation"),
    ("permissions-summary.json", "$.scanner_permissions[]"),
    ("permissions-summary.json", "$.permission_failures[]"),
    *(("permissions-summary.json", "$.permission_degradation." + key) for key in PERMISSION_COUNTS),
    *(("permissions-summary.json", "$.permission_degradation." + key + "[]") for key in ("stable_limitation_details", "degradation_details")),
}
