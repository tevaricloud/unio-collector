from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AwsApiMetric:  # noqa: D101
    request_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    late_request_count: int = 0
    late_success_count: int = 0
    late_failure_count: int = 0
    late_handled_absence_count: int = 0
    late_service_unavailable_count: int = 0
    late_throttle_count: int = 0
    late_permission_denied_count: int = 0
    handled_absence_count: int = 0
    service_unavailable_count: int = 0
    throttle_count: int = 0
    permission_denied_count: int = 0
    error_category_counts: dict[str, int] = field(default_factory=dict)
    expected_absence_reason_counts: dict[str, int] = field(default_factory=dict)
    service_availability_status_counts: dict[str, int] = field(default_factory=dict)
    page_count: int = 0
    result_count: int = 0
    resource_count: int = 0
    metric_datapoint_count: int = 0
    late_page_count: int = 0
    late_result_count: int = 0
    late_resource_count: int = 0
    late_metric_datapoint_count: int = 0
    latency_min_ms: float | None = None
    latency_max_ms: float | None = None
    latency_total_ms: float = 0.0
    rate_limit_wait_count: int = 0
    rate_limit_wait_total_ms: float = 0.0
    rate_limit_wait_max_ms: float = 0.0
    error_code_counts: dict[str, int] = field(default_factory=dict)
    replayed_count: int = 0

    def record(  # noqa: C901, D102
        self,
        *,
        status: str,
        latency_ms: float,
        expected_absence: bool = False,
        service_unavailable: bool = False,
        throttled: bool = False,
        permission_denied: bool = False,
        error_code: str | None = None,
        error_category: str | None = None,
        expected_absence_reason: str | None = None,
        service_availability_status: str | None = None,
        page_count: int = 1,
        result_count: int = 0,
        resource_count: int = 0,
        metric_datapoint_count: int = 0,
        rate_limit_wait_ms: float = 0.0,
        replayed: bool = False,
    ) -> None:
        self.request_count += 1
        if replayed:
            self.replayed_count += 1
        is_late = status in {"late_success", "late_failure"}
        if status == "late_success":
            self.late_request_count += 1
            self.late_success_count += 1
        elif status == "late_failure":
            self.late_request_count += 1
            self.late_failure_count += 1
        elif status == "success":
            self.success_count += 1
        elif expected_absence:
            self.handled_absence_count += 1
        else:
            self.failure_count += 1
        if is_late:
            if expected_absence:
                self.late_handled_absence_count += 1
            if throttled:
                self.late_throttle_count += 1
            if service_unavailable:
                self.late_service_unavailable_count += 1
            if permission_denied:
                self.late_permission_denied_count += 1
        else:
            if throttled:
                self.throttle_count += 1
            if service_unavailable:
                self.service_unavailable_count += 1
            if permission_denied:
                self.permission_denied_count += 1
        if error_code:
            self.error_code_counts[error_code] = self.error_code_counts.get(error_code, 0) + 1
        if error_category and error_category != "none":
            self.error_category_counts[error_category] = self.error_category_counts.get(error_category, 0) + 1
        if expected_absence_reason:
            self.expected_absence_reason_counts[expected_absence_reason] = self.expected_absence_reason_counts.get(expected_absence_reason, 0) + 1
        if service_availability_status and service_availability_status != "unknown":
            self.service_availability_status_counts[service_availability_status] = (
                self.service_availability_status_counts.get(
                    service_availability_status,
                    0,
                )
                + 1
            )
        if is_late:
            self.late_page_count += page_count
            self.late_result_count += result_count
            self.late_resource_count += resource_count
            self.late_metric_datapoint_count += metric_datapoint_count
        else:
            self.page_count += page_count
            self.result_count += result_count
            self.resource_count += resource_count
            self.metric_datapoint_count += metric_datapoint_count
        if rate_limit_wait_ms > 0:
            self.rate_limit_wait_count += 1
            self.rate_limit_wait_total_ms += rate_limit_wait_ms
            self.rate_limit_wait_max_ms = max(
                self.rate_limit_wait_max_ms,
                rate_limit_wait_ms,
            )
        self.latency_total_ms += latency_ms
        self.latency_min_ms = latency_ms if self.latency_min_ms is None else min(self.latency_min_ms, latency_ms)
        self.latency_max_ms = latency_ms if self.latency_max_ms is None else max(self.latency_max_ms, latency_ms)

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        average = self.latency_total_ms / self.request_count if self.request_count else 0.0
        wait_average = self.rate_limit_wait_total_ms / self.rate_limit_wait_count if self.rate_limit_wait_count else 0.0
        return {
            "request_count": self.request_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "late_request_count": self.late_request_count,
            "late_success_count": self.late_success_count,
            "late_failure_count": self.late_failure_count,
            "late_handled_absence_count": self.late_handled_absence_count,
            "late_service_unavailable_count": self.late_service_unavailable_count,
            "late_throttle_count": self.late_throttle_count,
            "late_permission_denied_count": self.late_permission_denied_count,
            "handled_absence_count": self.handled_absence_count,
            "service_unavailable_count": self.service_unavailable_count,
            "throttle_count": self.throttle_count,
            "permission_denied_count": self.permission_denied_count,
            "latency_min_ms": round(self.latency_min_ms or 0.0, 3),
            "latency_avg_ms": round(average, 3),
            "latency_max_ms": round(self.latency_max_ms or 0.0, 3),
            "rate_limit_wait_count": self.rate_limit_wait_count,
            "rate_limit_wait_total_ms": round(self.rate_limit_wait_total_ms, 3),
            "rate_limit_wait_avg_ms": round(wait_average, 3),
            "rate_limit_wait_max_ms": round(self.rate_limit_wait_max_ms, 3),
            "page_count": self.page_count,
            "result_count": self.result_count,
            "resource_count": self.resource_count,
            "metric_datapoint_count": self.metric_datapoint_count,
            "late_page_count": self.late_page_count,
            "late_result_count": self.late_result_count,
            "late_resource_count": self.late_resource_count,
            "late_metric_datapoint_count": self.late_metric_datapoint_count,
            "replayed_count": self.replayed_count,
            "error_code_counts": dict(sorted(self.error_code_counts.items())),
            "error_category_counts": dict(sorted(self.error_category_counts.items())),
            "expected_absence_reason_counts": dict(
                sorted(self.expected_absence_reason_counts.items()),
            ),
            "service_availability_status_counts": dict(
                sorted(self.service_availability_status_counts.items()),
            ),
        }
