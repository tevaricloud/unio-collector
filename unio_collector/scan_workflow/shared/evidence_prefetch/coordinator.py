from __future__ import annotations  # noqa: D100

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from unio_collector.scan_workflow.shared.evidence_prefetch.failure import (
    SharedEvidencePrefetchFailure,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.shared.evidence_prefetch.task import (
        SharedEvidencePrefetchTask,
    )


class SharedEvidencePrefetchCoordinator:
    """Runs independent shared-evidence prefetch tasks with bounded concurrency."""

    def __init__(  # noqa: D107
        self,
        *,
        max_workers: int,
        concurrency_enabled: bool,
        record_failure: Callable[[dict[str, object]], None],
    ) -> None:
        self.max_workers = max(1, max_workers)
        self.concurrency_enabled = concurrency_enabled
        self.record_failure = record_failure

    def run_tasks(self, tasks: list[SharedEvidencePrefetchTask]) -> None:
        """Run prefetch tasks sequentially or with bounded concurrency."""
        if not tasks:
            return
        if not self.concurrency_enabled or len(tasks) == 1:
            for task in tasks:
                self._run_task(task)
            return
        worker_count = min(self.max_workers, len(tasks))
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="unio-collector-prefetch",
        ) as executor:
            future_map = {executor.submit(self._run_task, task): task for task in tasks}
            for future in as_completed(future_map):
                future.result()

    def _run_task(self, task: SharedEvidencePrefetchTask) -> None:
        started = time.perf_counter()
        try:
            task.run()
        except Exception as exc:  # noqa: BLE001
            failure = SharedEvidencePrefetchFailure(
                task_name=task.name,
                error_code=exc.__class__.__name__,
                error_message=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
            self.record_failure(failure.convert_to_dict())
