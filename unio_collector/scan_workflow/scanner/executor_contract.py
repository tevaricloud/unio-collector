from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

from unio_collector.scan_workflow.scanner.helper_contract import (
    ScannerScheduleHelperRuntimeContract,
)
from unio_collector.scan_workflow.scanner.precheck_contract import (
    ScannerSkipRuntimeContract,
)

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView


class ScannerStageRuntimeContract(
    ScannerScheduleHelperRuntimeContract,
    ScannerSkipRuntimeContract,
    Protocol,
):
    """Runner fields required to execute scheduler stages."""

    @property
    def runtime_state(self) -> ScannerRuntimeStateView:
        """Return read-only scan runtime state."""
        ...
