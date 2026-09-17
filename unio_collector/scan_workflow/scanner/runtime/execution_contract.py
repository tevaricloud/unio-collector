from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

from unio_collector.scan_workflow.scanner.runtime.adapter_contract import (
    ScannerRuntimeAdapterTarget,
)

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.state import (
        ScannerRunnerNoteState,
        ScannerRunnerOutputState,
    )


class ScannerExecutionRuntimeContract(ScannerRuntimeAdapterTarget, Protocol):
    """Mutable scan state required to execute and record one scanner result."""

    @property
    def output_state(self) -> ScannerRunnerOutputState:
        """Return grouped scanner output state."""
        ...

    @property
    def note_state(self) -> ScannerRunnerNoteState:
        """Return grouped scanner note state."""
        ...
