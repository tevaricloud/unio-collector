from __future__ import annotations  # noqa: D100

import threading
from typing import Any

from unio_collector.aws.metric.api import AwsApiMetric


class AwsApiTelemetryRecorder:  # noqa: D101
    def __init__(self, *, enabled: bool = True) -> None:  # noqa: D107
        self.enabled = enabled
        self._metrics: dict[tuple[str, str, str, str, str, str], AwsApiMetric] = {}
        self._lock = threading.Lock()

    def record_call(  # noqa: D102
        self,
        *,
        scanner_id: str,
        account_id: str | None,
        region: str | None,
        service: str,
        operation: str,
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
        attempt_id: str | None = None,
    ) -> None:
        if not self.enabled:
            return
        key = (
            scanner_id,
            account_id or "unknown-account",
            region or "aws-global",
            service,
            operation,
            attempt_id or "",
        )
        with self._lock:
            metric = self._metrics.setdefault(key, AwsApiMetric())
            metric.record(
                status=status,
                latency_ms=latency_ms,
                expected_absence=expected_absence,
                service_unavailable=service_unavailable,
                throttled=throttled,
                permission_denied=permission_denied,
                error_code=error_code,
                error_category=error_category,
                expected_absence_reason=expected_absence_reason,
                service_availability_status=service_availability_status,
                page_count=page_count,
                result_count=result_count,
                resource_count=resource_count,
                metric_datapoint_count=metric_datapoint_count,
                rate_limit_wait_ms=rate_limit_wait_ms,
                replayed=replayed,
            )

    def convert_to_summary(self) -> dict[str, Any]:  # noqa: D102
        with self._lock:
            records = [
                {
                    "scanner_id": key[0],
                    "account_id": key[1],
                    "region": key[2],
                    "service": key[3],
                    "operation": key[4],
                    "attempt_id": key[5] or None,
                    **metric.convert_to_dict(),
                }
                for key, metric in sorted(self._metrics.items())
            ]
        return {
            "enabled": self.enabled,
            "records": records,
            "totals": self._build_totals(records),
        }

    def _build_totals(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        totals: dict[str, int | float] = {
            "request_count": 0,
            "success_count": 0,
            "failure_count": 0,
            "late_request_count": 0,
            "late_success_count": 0,
            "late_failure_count": 0,
            "late_handled_absence_count": 0,
            "late_service_unavailable_count": 0,
            "late_throttle_count": 0,
            "late_permission_denied_count": 0,
            "late_page_count": 0,
            "late_result_count": 0,
            "late_resource_count": 0,
            "late_metric_datapoint_count": 0,
            "handled_absence_count": 0,
            "service_unavailable_count": 0,
            "throttle_count": 0,
            "permission_denied_count": 0,
            "page_count": 0,
            "result_count": 0,
            "resource_count": 0,
            "metric_datapoint_count": 0,
            "replayed_count": 0,
            "rate_limit_wait_count": 0,
            "rate_limit_wait_total_ms": 0,
        }
        for record in records:
            for key, total in totals.items():
                value = record.get(key) or 0
                if key == "rate_limit_wait_total_ms":
                    totals[key] = round(float(total) + float(value), 3)
                else:
                    totals[key] = int(total) + int(value)
        return totals
