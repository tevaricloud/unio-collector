from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.progress import ScanProgressEvent
from unio_collector.scan_workflow.runner.merge import ScannerChildRunnerMergeService
from unio_collector.scan_workflow.scanner.child_runner_factory import (
    ScannerChildRunnerFactory,
)
from unio_collector.scanners.registry.catalog import get_scanner

if TYPE_CHECKING:
    from collections.abc import Sequence

    from unio_collector.scan_workflow.runner import ScannerRunner
    from unio_collector.scan_workflow.runner.merge_contract import (
        ScannerChildMergeRuntimeContract,
    )
    from unio_collector.scan_workflow.scanner.helper_contract import (
        ScannerScheduleHelperRuntimeContract,
    )
    from unio_collector.scan_workflow.scanner.result_builder import (
        ScannerScheduleResultBuilder,
    )
    from unio_collector.scan_workflow.scanner.runtime.dependencies import (
        ScannerRuntimeDependencies,
    )
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


class ScannerScheduleHelper:
    """Shared scheduler helpers for progress, failure, and merge handling."""

    def __init__(  # noqa: D107
        self,
        *,
        runner: ScannerScheduleHelperRuntimeContract,
        dependencies: ScannerRuntimeDependencies,
        result_builder: ScannerScheduleResultBuilder,
    ) -> None:
        self.runner = runner
        self.dependencies = dependencies
        self.result_builder = result_builder
        self.child_runner_factory = ScannerChildRunnerFactory()

    def build_dependency_skipped_result(
        self,
        scanner_id: str,
        *,
        dependency_id: str,
    ) -> ScannerExecutionResult:
        """Build a skipped result for a dependency-gated scanner."""
        return self.result_builder.build_dependency_skipped_result(
            scanner_id=scanner_id,
            dependency_id=dependency_id,
        )

    def build_scanner_timeout_result(
        self,
        scanner_id: str,
        *,
        duration_ms: int,
        timeout_seconds: int,
        extra_coverage_notes: Sequence[dict[str, Any]] | None = None,
        extra_limitations: Sequence[str] | None = None,
    ) -> ScannerExecutionResult:
        """Build a timeout result for a scanner child runner."""
        return self.result_builder.build_scanner_timeout_result(
            scanner_id=scanner_id,
            duration_ms=duration_ms,
            timeout_seconds=timeout_seconds,
            extra_coverage_notes=extra_coverage_notes,
            extra_limitations=extra_limitations,
        )

    def notify_skipped_scanner(
        self,
        result: ScannerExecutionResult,
        *,
        scanner_index: int | None,
    ) -> None:
        """Notify progress listeners that a scanner was skipped."""
        definition = get_scanner(result.scanner_id)
        if self.dependencies.progress is None:
            return
        self.dependencies.progress(
            ScanProgressEvent(
                event_type="scanner_completed",
                scanner_id=result.scanner_id,
                scanner_display_name=definition.display_name,
                scanner_index=scanner_index,
                scanner_total=self.dependencies.scanner_total,
                scanner_status=result.status,
                findings_count=result.findings_count,
                message=result.reason,
            ),
        )

    def notify(self, event: ScanProgressEvent) -> None:
        """Forward a progress event when a listener is configured."""
        if self.dependencies.progress:
            self.dependencies.progress(event)

    def build_scheduler_failure_runner(
        self,
        scanner_id: str,
        exc: Exception,
    ) -> ScannerRunner:
        """Create a child runner containing one scheduler failure result."""
        child = self.child_runner_factory.create_child_runner(
            parent=self.runner,
            progress=None,
            scanner_total=self.dependencies.scanner_total,
        )
        child.results.append(
            self.result_builder.build_scheduler_failure_result(
                scanner_id=scanner_id,
                exc=exc,
            ),
        )
        return child

    def merge_child_runner(
        self,
        child: ScannerChildMergeRuntimeContract,
    ) -> None:
        """Merge an isolated child runner back into the parent runner."""
        ScannerChildRunnerMergeService(self.runner).merge_child_runner(child)
