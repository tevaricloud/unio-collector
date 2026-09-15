"""Focused contract for scanner evidence payload recorder targets."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.state import ScannerRunnerOutputState


class ScannerEvidencePayloadRecorderTarget(Protocol):
    """Mutable payload collection required by the scanner evidence recorder."""

    @property
    def output_state(self) -> ScannerRunnerOutputState:
        """Return grouped scanner output state."""
        ...
