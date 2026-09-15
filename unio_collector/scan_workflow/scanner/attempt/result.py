from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.scan_workflow.scanner.attempt.outcome_reason import (
    ScannerAttemptOutcomeReason,
)

if TYPE_CHECKING:
    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext


@dataclass(frozen=True)
class ScannerAttemptRunResult[T]:
    """Scheduler-facing result for one supervised scanner attempt."""

    attempt: ScannerAttemptContext
    outcome_reason: ScannerAttemptOutcomeReason
    duration_ms: int
    value: T | None = None
    error: str | None = None
    exception_type: str | None = None

    @property
    def timed_out(self) -> bool:
        """Return whether deadline control owns the outcome."""
        return self.outcome_reason in {
            ScannerAttemptOutcomeReason.EXPLICIT_CANCELLATION,
            ScannerAttemptOutcomeReason.DEADLINE_EXPIRED,
            ScannerAttemptOutcomeReason.SCHEDULER_TIMEOUT,
        }
