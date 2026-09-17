from __future__ import annotations  # noqa: D100

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, TypeVar

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.collection.helpers import count_collection_results
from unio_collector.aws.collection.task_result import AwsCollectionTaskResult

if TYPE_CHECKING:
    from collections.abc import Iterable

    from unio_collector.aws.collection.task import AwsCollectionTask, AwsCollectionTaskStatus

T = TypeVar("T")


class AwsCollectionExecutor:
    """Runs bounded AWS collection tasks and returns structured results."""

    def __init__(self, *, max_workers: int) -> None:  # noqa: D107
        if max_workers <= 0:
            msg = "Collection max_workers must be a positive integer."
            raise ValueError(msg)
        self.max_workers = max_workers

    def run(  # noqa: D102
        self,
        tasks: Iterable[AwsCollectionTask[T]],
    ) -> list[AwsCollectionTaskResult[T]]:
        task_list = list(tasks)
        if not task_list:
            return []
        worker_count = min(self.max_workers, len(task_list))
        results_by_index: dict[int, AwsCollectionTaskResult[T]] = {}
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="unio-collector-aws-collection",
        ) as executor:
            future_map = {executor.submit(self._execute_task, task): index for index, task in enumerate(task_list)}
            for future in as_completed(future_map):
                results_by_index[future_map[future]] = future.result()
        return [results_by_index[index] for index in range(len(task_list)) if index in results_by_index]

    def _execute_task(
        self,
        task: AwsCollectionTask[T],
    ) -> AwsCollectionTaskResult[T]:
        started = time.perf_counter()
        try:
            value = task.collect()
        except Exception as exc:  # noqa: BLE001
            return AwsCollectionTaskResult(
                task=task,
                status=self._classify_exception(exc),
                duration_ms=self._get_duration_ms(started),
                error_code=aws_errors.get_aws_error_code(exc),
                error_message=str(exc),
            )
        counts = count_collection_results(task, value)
        return AwsCollectionTaskResult(
            task=task,
            status="completed",
            duration_ms=self._get_duration_ms(started),
            value=value,
            result_count=counts.result_count,
            resource_count=counts.resource_count,
            metric_datapoint_count=counts.metric_datapoint_count,
            page_count=counts.page_count,
        )

    def _classify_exception(self, exc: Exception) -> AwsCollectionTaskStatus:
        if aws_errors.is_permission_error(exc):
            return "permission_denied"
        if aws_errors.is_throttling_error(exc):
            return "throttled"
        if aws_errors.is_unsupported_region_error(exc):
            return "unsupported_region"
        return "failed"

    def _get_duration_ms(self, started: float) -> int:
        return int((time.perf_counter() - started) * 1000)
