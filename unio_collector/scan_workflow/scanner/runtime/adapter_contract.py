from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.evidence_gateway import (
        ScannerRunnerEvidenceGateway,
    )
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.runner.state import (
        ScannerRunnerContextState,
        ScannerRunnerNoteState,
        ScannerRunnerOutputState,
    )
    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext
    from unio_collector.scan_workflow.scanner.runtime.cancellation import (
        ScannerCancellationToken,
    )


class ScannerRuntimeAdapterTarget(Protocol):
    """Mutable scan state required by the scanner-facing runtime adapter."""

    @property
    def context_state(self) -> ScannerRunnerContextState:
        """Return grouped scan-context state."""
        ...

    @property
    def output_state(self) -> ScannerRunnerOutputState:
        """Return grouped scanner output state."""
        ...

    @property
    def runtime_state(self) -> ScannerRuntimeStateView:
        """Return read-only runtime state."""
        ...

    @property
    def note_state(self) -> ScannerRunnerNoteState:
        """Return grouped scanner note state."""
        ...

    @property
    def evidence_gateway(self) -> ScannerRunnerEvidenceGateway:
        """Return the scanner evidence gateway."""
        ...

    @property
    def cancellation_token(self) -> ScannerCancellationToken:
        """Return scanner cancellation state."""
        ...

    @property
    def active_attempt(self) -> ScannerAttemptContext | None:
        """Return the active scanner attempt."""
        ...
