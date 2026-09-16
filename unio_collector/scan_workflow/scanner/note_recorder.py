from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scan_workflow.scanner.scan_note_target import (
        ScannerRunNoteRecorderTarget,
    )


class ScannerRunNoteRecorder:
    """Record scanner warnings and coverage notes on runtime state."""

    def __init__(self, runtime: ScannerRunNoteRecorderTarget) -> None:  # noqa: D107
        self._runtime = runtime

    def add_scanner_warning(self, scanner_id: str, warning: str) -> None:
        """Record a warning emitted by a scanner run."""
        self._runtime.note_state.scanner_warnings.setdefault(scanner_id, []).append(
            warning,
        )

    def add_scanner_coverage_note(
        self,
        scanner_id: str,
        note: dict[str, Any],
    ) -> None:
        """Record a non-warning coverage note emitted by a scanner run."""
        self._runtime.note_state.scanner_coverage_notes.setdefault(scanner_id, []).append(
            note,
        )
