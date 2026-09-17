from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.runner.state import (
        ScannerRunnerEvidenceState,
        ScannerRunnerOutputState,
        ScannerRunnerScheduleState,
    )


class ScannerSummaryRuntimeContract(Protocol):
    """Read-only runner fields required to build scan runtime summaries."""

    @property
    def runtime_state(self) -> ScannerRuntimeStateView: ...  # noqa: D102

    @property
    def output_state(self) -> ScannerRunnerOutputState: ...  # noqa: D102

    @property
    def evidence_state(self) -> ScannerRunnerEvidenceState: ...  # noqa: D102

    @property
    def schedule_state(self) -> ScannerRunnerScheduleState: ...  # noqa: D102
