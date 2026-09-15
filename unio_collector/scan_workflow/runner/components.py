from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.state import (
        ScannerRunnerContextState,
        ScannerRunnerEvidenceState,
        ScannerRunnerNoteState,
        ScannerRunnerOutputState,
        ScannerRunnerScheduleState,
    )


@dataclass(frozen=True)
class ScannerRuntimeComponents:
    """Complete grouped state owned by one scanner runner."""

    context_state: ScannerRunnerContextState
    output_state: ScannerRunnerOutputState
    note_state: ScannerRunnerNoteState
    evidence_state: ScannerRunnerEvidenceState
    schedule_state: ScannerRunnerScheduleState
