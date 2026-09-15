from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

from unio_collector.scan_workflow.scanner.executor_contract import (
    ScannerStageRuntimeContract,
)

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.state import ScannerRunnerScheduleState


class ScannerScheduleRuntimeContract(ScannerStageRuntimeContract, Protocol):
    """Runner fields required to plan and record scanner scheduler stages."""

    @property
    def schedule_state(self) -> ScannerRunnerScheduleState:
        """Return grouped scanner scheduler state."""
        ...
