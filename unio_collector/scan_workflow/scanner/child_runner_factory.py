from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scan_workflow.runner import ScannerRunner

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.progress import ScanProgressEvent
    from unio_collector.scan_workflow.scanner.runner_parent_contract import (
        ScannerChildRunnerParentContract,
    )


class ScannerChildRunnerFactory:
    """Create isolated scanner child runners for scheduler collaborators."""

    def create_child_runner(
        self,
        *,
        parent: ScannerChildRunnerParentContract,
        progress: Callable[[ScanProgressEvent], None] | None,
        scanner_total: int | None,
    ) -> ScannerRunner:
        """Create a child runner sharing the parent's immutable scan context."""
        return ScannerRunner(
            parent.context_state.state,
            progress=progress,
            scanner_total=scanner_total,
        )

    def create_inherited_child_runner(
        self,
        *,
        parent: ScannerChildRunnerParentContract,
        progress: Callable[[ScanProgressEvent], None] | None,
        scanner_total: int | None,
    ) -> ScannerRunner:
        """Create a child runner with inherited period and service-delta context."""
        child = self.create_child_runner(
            parent=parent,
            progress=progress,
            scanner_total=scanner_total,
        )
        child.context_state.inherit_cost_periods(
            parent.context_state.previous_period,
            parent.context_state.current_period,
        )
        child.output_state.inherit_service_deltas(parent.output_state.service_deltas)
        return child
