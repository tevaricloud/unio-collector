from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.state import (
        ScannerRunnerNoteState,
        ScannerRunnerOutputState,
    )


class ScannerChildMergeRuntimeContract(Protocol):
    """Mutable runner fields required to merge isolated child output."""

    @property
    def output_state(self) -> ScannerRunnerOutputState: ...  # noqa: D102

    @property
    def note_state(self) -> ScannerRunnerNoteState: ...  # noqa: D102
