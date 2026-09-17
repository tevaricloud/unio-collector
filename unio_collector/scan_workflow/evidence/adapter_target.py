"""Focused contract for the evidence runtime adapter target."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext
    from unio_collector.scan_workflow.scanner.runtime.cancellation import (
        ScannerCancellationToken,
    )


class ScannerEvidenceRuntimeAdapterTarget(Protocol):
    """Context fields required by the evidence-runtime adapter."""

    @property
    def runtime_state(self) -> ScannerRuntimeStateView: ...  # noqa: D102

    @property
    def cancellation_token(self) -> ScannerCancellationToken: ...  # noqa: D102

    @property
    def active_attempt(self) -> ScannerAttemptContext | None: ...  # noqa: D102
