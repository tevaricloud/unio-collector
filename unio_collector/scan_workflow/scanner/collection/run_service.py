from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scan_workflow.scanner.collection.dependency_factory import (
    ScannerCollectionDependencyFactory,
)
from unio_collector.scan_workflow.scanner.collection.service import ScannerCollectionService
from unio_collector.scan_workflow.scanner.schedule.service import ScannerScheduleService

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.progress import ScanProgressEvent
    from unio_collector.scan_workflow.scanner.entrypoint_contract import (
        ScannerRunRuntimeContract,
    )


class ScannerCollectionRunService:
    """Run selected scanners through the scheduler without scanner analysis."""

    def __init__(  # noqa: D107
        self,
        dependency_factory: ScannerCollectionDependencyFactory | None = None,
    ) -> None:
        self.dependency_factory = dependency_factory or ScannerCollectionDependencyFactory()

    def run_many(
        self,
        runner: ScannerRunRuntimeContract,
        scanner_ids: tuple[str, ...] | list[str],
        *,
        progress: Callable[[ScanProgressEvent], None] | None,
        scanner_total: int | None,
    ) -> None:
        """Collect selected scanner evidence through shared scheduler behavior."""
        runner.evidence_gateway.prefetch_shared_evidence(scanner_ids)
        dependencies = self.dependency_factory.create_dependencies(
            progress=progress,
            scanner_total=scanner_total,
        )
        ScannerScheduleService(
            runner,
            dependencies,
            scanner_operation=ScannerCollectionService(dependencies),
        ).run_many(scanner_ids)
