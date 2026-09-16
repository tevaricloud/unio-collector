from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.scan_workflow.evidence.cost.explorer import (
    SHARED_COST_EXPLORER_DAILY_COST_CONSUMERS,
)
from unio_collector.scan_workflow.evidence.s3 import (
    SHARED_S3_BUCKET_INDEX_CONSUMERS,
)
from unio_collector.scan_workflow.shared.evidence import SharedEvidencePrefetchTask

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class SharedEvidencePrefetchPolicy:
    """Decides which shared evidence prefetches apply to a scanner set."""

    scanner_ids: tuple[str, ...]

    @classmethod
    def create(cls, scanner_ids: tuple[str, ...] | list[str]) -> SharedEvidencePrefetchPolicy:  # noqa: D102
        return cls(scanner_ids=tuple(scanner_ids))

    def should_prefetch_s3_bucket_index(self) -> bool:  # noqa: D102
        return any(scanner_id in SHARED_S3_BUCKET_INDEX_CONSUMERS for scanner_id in self.scanner_ids)

    def should_prefetch_cost_explorer_daily_costs(self) -> bool:  # noqa: D102
        enabled_scanner_ids = set(self.scanner_ids)
        return any(enabled_scanner_ids.intersection(consumers) for consumers in SHARED_COST_EXPLORER_DAILY_COST_CONSUMERS.values())

    def build_tasks(  # noqa: D102
        self,
        *,
        prefetch_s3_bucket_index: Callable[[], None],
        prefetch_cost_explorer_daily_costs: Callable[[], None],
    ) -> list[SharedEvidencePrefetchTask]:
        tasks: list[SharedEvidencePrefetchTask] = []
        if self.should_prefetch_s3_bucket_index():
            tasks.append(
                SharedEvidencePrefetchTask(
                    name="s3_bucket_index",
                    run=prefetch_s3_bucket_index,
                ),
            )
        if self.should_prefetch_cost_explorer_daily_costs():
            tasks.append(
                SharedEvidencePrefetchTask(
                    name="cost_explorer_daily_costs",
                    run=prefetch_cost_explorer_daily_costs,
                ),
            )
        return tasks
