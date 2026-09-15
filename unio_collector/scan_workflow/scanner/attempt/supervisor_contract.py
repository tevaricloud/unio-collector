from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext
    from unio_collector.scan_workflow.scanner.attempt.result import ScannerAttemptRunResult
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


class ScannerAttemptSupervisorContract(Protocol):
    """Structural boundary used by the scanner stage executor."""

    def run(
        self,
        attempt: ScannerAttemptContext,
        func: Callable[[], ScannerExecutionResult],
    ) -> ScannerAttemptRunResult[ScannerExecutionResult]:
        """Run a scanner attempt under bounded supervision."""
        ...
