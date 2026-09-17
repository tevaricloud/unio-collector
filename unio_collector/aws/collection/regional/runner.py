from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, TypeVar

from unio_collector.aws.collection.executor import AwsCollectionExecutor
from unio_collector.aws.collection.helpers import record_collection_results
from unio_collector.aws.collection.regional.result import RegionalCollectionResult
from unio_collector.aws.collection.task import AwsCollectionTask

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.collection.task_result import AwsCollectionTaskResult

T = TypeVar("T")


class RegionalAwsCollectionRunner:
    """Builds per-region collection tasks using the shared runtime worker limit."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str | None,
        audit_context: AwsAuditContext,
        collector_id: str,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.collector_id = collector_id

    def collect_region_lists(  # noqa: D102
        self,
        *,
        regions: Iterable[str],
        service: str,
        operation: str,
        collect_region: Callable[[str], list[T]],
    ) -> RegionalCollectionResult[T]:
        tasks = [
            AwsCollectionTask(
                name=f"{self.collector_id}:{service}:{operation}:{region}",
                scanner_id=self.audit_context.scanner_id,
                collector_id=self.collector_id,
                account_id=self.account_id,
                region=region,
                service=service,
                operation=operation,
                collect=lambda region=region: collect_region(region),
            )
            for region in regions
        ]
        executor = AwsCollectionExecutor(
            max_workers=self.session.runtime_config.max_workers,
        )
        task_results = executor.run(tasks)
        self._record_task_results(task_results)
        values: list[T] = []
        for result in task_results:
            if result.status == "completed" and result.value:
                values.extend(result.value)
        return RegionalCollectionResult(
            values=values,
            task_results=task_results,
        )

    def _record_task_results(
        self,
        task_results: list[AwsCollectionTaskResult[list[T]]],
    ) -> None:
        record_collection_results(self.session, task_results)
