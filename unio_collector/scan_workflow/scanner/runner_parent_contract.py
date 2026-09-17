from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.state import (
        ScannerRunnerContextState,
        ScannerRunnerOutputState,
    )


class ScannerChildRunnerParentContract(Protocol):
    """Parent runner fields required to create isolated scanner child runners."""

    @property
    def context_state(self) -> ScannerRunnerContextState:
        """Return grouped scan-context state."""
        ...

    @property
    def output_state(self) -> ScannerRunnerOutputState:
        """Return grouped scanner output state."""
        ...
