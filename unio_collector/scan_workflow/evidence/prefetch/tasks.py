from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.scan_workflow.evidence.prefetch.policy import (
    SharedEvidencePrefetchPolicy,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.shared.evidence import SharedEvidencePrefetchTask


@dataclass(frozen=True)
class SharedEvidencePrefetchTaskBuilder:
    """Builds prefetch tasks and execution sizing from scanner selection."""

    scanner_ids: tuple[str, ...]

    @classmethod
    def create(  # noqa: D102
        cls,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> SharedEvidencePrefetchTaskBuilder:
        return cls(scanner_ids=tuple(scanner_ids))

    def build_tasks(  # noqa: D102
        self,
        *,
        prefetch_s3_bucket_index: Callable[[], None],
        prefetch_cost_explorer_daily_costs: Callable[[], None],
    ) -> list[SharedEvidencePrefetchTask]:
        return SharedEvidencePrefetchPolicy.create(self.scanner_ids).build_tasks(
            prefetch_s3_bucket_index=prefetch_s3_bucket_index,
            prefetch_cost_explorer_daily_costs=prefetch_cost_explorer_daily_costs,
        )

    def get_worker_count(  # noqa: D102
        self,
        *,
        configured_max_workers: int,
        tasks: list[SharedEvidencePrefetchTask],
    ) -> int:
        return max(1, min(max(1, configured_max_workers), len(tasks) or 1))

    def should_prefetch_s3_bucket_index(self) -> bool:  # noqa: D102
        return SharedEvidencePrefetchPolicy.create(self.scanner_ids).should_prefetch_s3_bucket_index()

    def should_prefetch_cost_explorer_daily_costs(self) -> bool:  # noqa: D102
        return SharedEvidencePrefetchPolicy.create(self.scanner_ids).should_prefetch_cost_explorer_daily_costs()
