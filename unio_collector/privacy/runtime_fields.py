"""Finite privacy schemas for API and collection runtime telemetry."""

from __future__ import annotations

from typing import Any

API_RUNTIME_FIELDS = {
    "": "safe_metadata",
    "enabled": "safe_metadata",
    "records": "sequence",
    "records[]": "safe_metadata",
    "totals": "safe_metadata",
    "records[].account_id": "aws_account_id",
    "records[].attempt_id": "resource_id",
    "records[].region": "region",
    **dict.fromkeys(("records[].scanner_id", "records[].service", "records[].operation"), "free_text"),
    **{
        f"records[].{key}": "safe_metadata"
        for key in (
            "failure_count",
            "handled_absence_count",
            "late_failure_count",
            "late_handled_absence_count",
            "late_metric_datapoint_count",
            "late_page_count",
            "late_permission_denied_count",
            "late_request_count",
            "late_resource_count",
            "late_result_count",
            "late_service_unavailable_count",
            "late_success_count",
            "late_throttle_count",
            "latency_avg_ms",
            "latency_max_ms",
            "latency_min_ms",
            "metric_datapoint_count",
            "page_count",
            "permission_denied_count",
            "rate_limit_wait_avg_ms",
            "rate_limit_wait_count",
            "rate_limit_wait_max_ms",
            "rate_limit_wait_total_ms",
            "replayed_count",
            "request_count",
            "resource_count",
            "result_count",
            "service_unavailable_count",
            "success_count",
            "throttle_count",
        )
    },
    **{
        f"records[].{key}": "diagnostic_counts"
        for key in ("error_category_counts", "error_code_counts", "expected_absence_reason_counts", "service_availability_status_counts")
    },
    **{
        f"totals.{key}": "safe_metadata"
        for key in (
            "failure_count",
            "handled_absence_count",
            "late_failure_count",
            "late_handled_absence_count",
            "late_metric_datapoint_count",
            "late_page_count",
            "late_permission_denied_count",
            "late_request_count",
            "late_resource_count",
            "late_result_count",
            "late_service_unavailable_count",
            "late_success_count",
            "late_throttle_count",
            "metric_datapoint_count",
            "page_count",
            "permission_denied_count",
            "rate_limit_wait_count",
            "rate_limit_wait_total_ms",
            "replayed_count",
            "request_count",
            "resource_count",
            "result_count",
            "service_unavailable_count",
            "success_count",
            "throttle_count",
        )
    },
}

_TASK_COUNTS = (
    "task_count",
    "completed_count",
    "failed_count",
    "result_count",
    "resource_count",
    "metric_datapoint_count",
    "page_count",
    "cumulative_task_duration_ms",
    "max_task_duration_ms",
    "average_task_duration_ms",
)
_GROUP_IDENTITIES = ("scanner_id", "account_id", "region", "service", "operation")
_GROUP_COUNTS = ("status_counts", "error_code_counts", "services", "regions")
COLLECTION_RUNTIME_FIELDS = {
    "": "safe_metadata",
    **dict.fromkeys(
        (
            "task_count",
            "failed_task_count",
            "result_count",
            "resource_count",
            "metric_datapoint_count",
            "page_count",
            "cumulative_task_duration_ms",
            "average_task_duration_ms",
            "contains_client_result_data",
        ),
        "safe_metadata",
    ),
    "duration_note": "free_text",
    **dict.fromkeys(("by_scanner", "by_operation", "by_throttle_domain"), "diagnostic_groups"),
    "slowest_tasks": "sequence",
    "slowest_tasks[]": "safe_metadata",
    **{f"slowest_tasks[].{key}": "safe_metadata" for key in ("duration_ms", "result_count", "resource_count", "metric_datapoint_count", "page_count")},
    **{f"slowest_tasks[].{key}": "free_text" for key in ("scanner_id", "collector_id", "service", "operation", "status", "error_code")},
    "slowest_tasks[].name": "resource_name",
    "slowest_tasks[].account_id": "aws_account_id",
    "slowest_tasks[].region": "region",
    "slowest_tasks[].error_message": "removed_diagnostic",
}


def valid_diagnostic_counts(value: Any) -> bool:  # noqa: ANN401
    """Admit only string-label/non-negative-integer count maps for omission."""
    return isinstance(value, dict) and all(isinstance(key, str) and type(count) is int and count >= 0 for key, count in value.items())


def unknown_diagnostic_groups(value: Any, member: str, path: str) -> list[str]:  # noqa: ANN401
    """Check finite group fields before omitting identifier-bearing map labels."""
    if not isinstance(value, dict):
        return [member + path[1:]]
    group_type = path.rsplit(".", 1)[-1]
    identities = () if group_type == "by_scanner" else _GROUP_IDENTITIES if group_type == "by_operation" else ("account_id", "region", "service")
    count_maps = ("status_counts", "services", "regions") if group_type == "by_scanner" else ("status_counts", "error_code_counts")
    allowed = {*_TASK_COUNTS, *identities, *count_maps}
    errors = []
    for label, record in value.items():
        record_path = member + path[1:] + "." + str(label)
        if not isinstance(label, str) or not isinstance(record, dict):
            errors.append(record_path)
            continue
        for key, child in record.items():
            if (
                key not in allowed
                or (key in count_maps and not valid_diagnostic_counts(child))
                or (key in _TASK_COUNTS and (type(child) is not int or child < 0))
                or (key in identities and not isinstance(child, str))
            ):
                errors.append(record_path + "." + str(key))
    return errors


def diagnostic_errors(category: str | None, value: Any, member: str, path: str) -> list[str] | None:  # noqa: ANN401
    """Validate the two explicit opaque diagnostic structures before omission."""
    if category == "diagnostic_counts":
        return [] if valid_diagnostic_counts(value) else [member + path[1:]]
    if category == "diagnostic_groups":
        return unknown_diagnostic_groups(value, member, path)
    return None
