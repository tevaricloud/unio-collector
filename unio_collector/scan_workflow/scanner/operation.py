from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scan_workflow.scanner.runtime.execution_contract import (
        ScannerExecutionRuntimeContract,
    )
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


class ScannerOperation(Protocol):
    """Operation executed for one scheduled scanner."""

    def run_scanner(
        self,
        runner: ScannerExecutionRuntimeContract,
        scanner_id: str,
        *,
        scanner_index: int | None = None,
    ) -> ScannerExecutionResult:
        """Run one scheduled scanner operation."""
        ...
