from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from unio_collector.scan_workflow.scanner.runtime.cancellation import (
    ScannerCancellationToken,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.core.cost_period import CostPeriod
    from unio_collector.scan_workflow.aws.scan.state import AwsScanState
    from unio_collector.scan_workflow.progress import ScanProgressEvent
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext


@dataclass
class ScannerRunnerContextState:
    """Core scan context shared by runtime collaborators."""

    state: AwsScanState
    runtime_state: ScannerRuntimeStateView
    progress: Callable[[ScanProgressEvent], None] | None
    scanner_total: int | None
    previous_period: CostPeriod
    current_period: CostPeriod
    cancellation_token: ScannerCancellationToken = field(
        default_factory=ScannerCancellationToken,
    )
    active_attempt: ScannerAttemptContext | None = None

    def bind_attempt(self, attempt: ScannerAttemptContext) -> None:
        """Bind the attempt currently authorized to use this runner state."""
        self.active_attempt = attempt

    def inherit_cost_periods(
        self,
        previous_period: CostPeriod,
        current_period: CostPeriod,
    ) -> None:
        """Copy the parent runner's resolved cost periods."""
        self.previous_period = previous_period
        self.current_period = current_period
