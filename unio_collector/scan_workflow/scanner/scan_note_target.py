"""Focused contract for scanner note recorder targets."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.state import ScannerRunnerNoteState


class ScannerRunNoteRecorderTarget(Protocol):
    """Mutable note collections required by the scanner note recorder."""

    @property
    def note_state(self) -> ScannerRunnerNoteState:
        """Return grouped scanner note state."""
        ...
