from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

from unio_collector.scan_workflow.scanner.runner_parent_contract import (
    ScannerChildRunnerParentContract,
)

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.state import (
        ScannerRunnerOutputState,
        ScannerRunnerScheduleState,
    )


class ScannerSkipRuntimeContract(ScannerChildRunnerParentContract, Protocol):
    """Runner fields required to evaluate precheck and dependency skips."""

    @property
    def output_state(self) -> ScannerRunnerOutputState:
        """Return grouped scanner output state."""
        ...

    @property
    def schedule_state(self) -> ScannerRunnerScheduleState:
        """Return grouped scheduler state."""
        ...
