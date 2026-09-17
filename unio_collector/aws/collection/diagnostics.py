from __future__ import annotations  # noqa: D100

import threading
from typing import TYPE_CHECKING, Any

from unio_collector.aws.collection.helpers import format_collection_task_warning

if TYPE_CHECKING:
    from collections.abc import Iterable

    from unio_collector.aws.collection.task_result import AwsCollectionTaskResult


class AwsCollectionDiagnostics:
    """Thread-safe store for structured AWS collection task outcomes."""

    def __init__(self) -> None:  # noqa: D107
        self._results: list[AwsCollectionTaskResult[Any]] = []
        self._lock = threading.Lock()

    def record_results(  # noqa: D102
        self,
        results: Iterable[AwsCollectionTaskResult[Any]],
    ) -> None:
        with self._lock:
            self._results.extend(results)

    def count(self) -> int:  # noqa: D102
        with self._lock:
            return len(self._results)

    def get_results_since(  # noqa: D102
        self,
        start_index: int,
        *,
        scanner_id: str | None = None,
    ) -> list[AwsCollectionTaskResult[Any]]:
        with self._lock:
            results = list(self._results[start_index:])
        if scanner_id is None:
            return results
        return [result for result in results if result.task.scanner_id == scanner_id]

    def build_warning_messages_since(  # noqa: D102
        self,
        start_index: int,
        *,
        scanner_id: str | None = None,
    ) -> list[str]:
        return [
            format_collection_task_warning(result)
            for result in self.get_results_since(
                start_index,
                scanner_id=scanner_id,
            )
            if result.status != "completed"
        ]

    def convert_to_summary(self) -> dict[str, Any]:  # noqa: D102
        with self._lock:
            results = list(self._results)
        by_scanner: dict[str, dict[str, Any]] = {}
        for result in results:
            scanner_summary = by_scanner.setdefault(
                result.task.scanner_id,
                {
                    "task_count": 0,
                    "completed_count": 0,
                    "failed_count": 0,
                    "status_counts": {},
                    "services": {},
                    "regions": {},
                    "result_count": 0,
                    "resource_count": 0,
                    "metric_datapoint_count": 0,
                    "page_count": 0,
                    "cumulative_task_duration_ms": 0,
                    "max_task_duration_ms": 0,
                },
            )
            scanner_summary["task_count"] += 1
            scanner_summary["result_count"] += result.result_count
            scanner_summary["resource_count"] += result.resource_count
            scanner_summary["metric_datapoint_count"] += result.metric_datapoint_count
            scanner_summary["page_count"] += result.page_count
            scanner_summary["cumulative_task_duration_ms"] += result.duration_ms
            scanner_summary["max_task_duration_ms"] = max(
                int(scanner_summary["max_task_duration_ms"]),
                result.duration_ms,
            )
            status_counts = scanner_summary["status_counts"]
            status_counts[result.status] = int(status_counts.get(result.status) or 0) + 1
            if result.status == "completed":
                scanner_summary["completed_count"] += 1
            else:
                scanner_summary["failed_count"] += 1
            services = scanner_summary["services"]
            services[result.task.service] = int(services.get(result.task.service) or 0) + 1
            regions = scanner_summary["regions"]
            region = result.task.region or "aws-global"
            regions[region] = int(regions.get(region) or 0) + 1
        self._add_average_task_durations(by_scanner)
        cumulative_duration = sum(result.duration_ms for result in results)
        return {
            "task_count": len(results),
            "failed_task_count": sum(1 for result in results if result.status != "completed"),
            "result_count": sum(result.result_count for result in results),
            "resource_count": sum(result.resource_count for result in results),
            "metric_datapoint_count": sum(result.metric_datapoint_count for result in results),
            "page_count": sum(result.page_count for result in results),
            "cumulative_task_duration_ms": cumulative_duration,
            "average_task_duration_ms": self._calculate_average_duration(
                cumulative_duration,
                len(results),
            ),
            "duration_note": (
                "Collection task durations are cumulative across concurrent "
                "worker tasks; compare scan wall-clock runtime using "
                "workflow-timing.json total_duration_ms."
            ),
            "slowest_tasks": [
                result.convert_to_dict()
                for result in sorted(
                    results,
                    key=lambda item: item.duration_ms,
                    reverse=True,
                )[:10]
            ],
            "by_scanner": by_scanner,
            "by_operation": self._build_operation_summary(results),
            "by_throttle_domain": self._build_throttle_domain_summary(results),
            "contains_client_result_data": False,
        }

    def _build_operation_summary(
        self,
        results: list[AwsCollectionTaskResult[Any]],
    ) -> dict[str, dict[str, Any]]:
        summary: dict[str, dict[str, Any]] = {}
        for result in results:
            key = "|".join(
                (
                    result.task.scanner_id,
                    result.task.account_id or "unknown-account",
                    result.task.region or "aws-global",
                    result.task.service,
                    result.task.operation,
                ),
            )
            item = summary.setdefault(
                key,
                self._build_empty_task_group(
                    scanner_id=result.task.scanner_id,
                    account_id=result.task.account_id or "unknown-account",
                    region=result.task.region or "aws-global",
                    service=result.task.service,
                    operation=result.task.operation,
                ),
            )
            self._add_result_to_task_group(item, result)
        self._add_average_task_durations(summary)
        return summary

    def _build_throttle_domain_summary(
        self,
        results: list[AwsCollectionTaskResult[Any]],
    ) -> dict[str, dict[str, Any]]:
        summary: dict[str, dict[str, Any]] = {}
        for result in results:
            key = "|".join(
                (
                    result.task.account_id or "unknown-account",
                    result.task.region or "aws-global",
                    result.task.service,
                ),
            )
            item = summary.setdefault(
                key,
                self._build_empty_task_group(
                    account_id=result.task.account_id or "unknown-account",
                    region=result.task.region or "aws-global",
                    service=result.task.service,
                ),
            )
            self._add_result_to_task_group(item, result)
        self._add_average_task_durations(summary)
        return summary

    def _build_empty_task_group(self, **identity: Any) -> dict[str, Any]:  # noqa: ANN401
        return {
            **identity,
            "task_count": 0,
            "completed_count": 0,
            "failed_count": 0,
            "status_counts": {},
            "error_code_counts": {},
            "result_count": 0,
            "resource_count": 0,
            "metric_datapoint_count": 0,
            "page_count": 0,
            "cumulative_task_duration_ms": 0,
            "max_task_duration_ms": 0,
        }

    def _add_result_to_task_group(
        self,
        item: dict[str, Any],
        result: AwsCollectionTaskResult[Any],
    ) -> None:
        item["task_count"] += 1
        item["result_count"] += result.result_count
        item["resource_count"] += result.resource_count
        item["metric_datapoint_count"] += result.metric_datapoint_count
        item["page_count"] += result.page_count
        item["cumulative_task_duration_ms"] += result.duration_ms
        item["max_task_duration_ms"] = max(
            int(item["max_task_duration_ms"]),
            result.duration_ms,
        )
        status_counts = item["status_counts"]
        status_counts[result.status] = int(status_counts.get(result.status) or 0) + 1
        if result.status == "completed":
            item["completed_count"] += 1
        else:
            item["failed_count"] += 1
        if result.error_code:
            error_counts = item["error_code_counts"]
            error_counts[result.error_code] = int(error_counts.get(result.error_code) or 0) + 1

    def _add_average_task_durations(
        self,
        by_scanner: dict[str, dict[str, Any]],
    ) -> None:
        for scanner_summary in by_scanner.values():
            task_count = int(scanner_summary.get("task_count") or 0)
            cumulative_duration = int(
                scanner_summary.get("cumulative_task_duration_ms") or 0,
            )
            scanner_summary["average_task_duration_ms"] = self._calculate_average_duration(cumulative_duration, task_count)

    def _calculate_average_duration(
        self,
        cumulative_duration_ms: int,
        task_count: int,
    ) -> int:
        if task_count <= 0:
            return 0
        return int(cumulative_duration_ms / task_count)
