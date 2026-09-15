from __future__ import annotations  # noqa: D100

import threading
import time
from dataclasses import dataclass, field

from unio_collector.scan_workflow.scanner.runtime.cancellation_error import (
    ScannerDeadlineExceededError,
)


@dataclass
class ScannerCancellationToken:
    """Cooperative scanner cancellation and deadline state."""

    deadline_perf: float | None = None
    reason: str = "Scanner execution was cancelled."
    _cancelled: threading.Event = field(default_factory=threading.Event)

    @classmethod
    def from_timeout_seconds(
        cls,
        timeout_seconds: float | None,
    ) -> ScannerCancellationToken:
        """Create a token with a monotonic deadline derived from a timeout."""
        if timeout_seconds is None:
            return cls()
        return cls(deadline_perf=time.perf_counter() + float(timeout_seconds))

    def cancel(self, reason: str | None = None) -> None:
        """Mark the scanner as cancelled for cooperative callers."""
        if reason:
            self.reason = reason
        self._cancelled.set()

    def is_cancelled(self) -> bool:
        """Return whether cancellation was requested or the deadline has passed."""
        if self._cancelled.is_set():
            return True
        if self.deadline_perf is not None and time.perf_counter() >= self.deadline_perf:
            self.cancel("Scanner deadline expired before this work could start.")
            return True
        return False

    def time_remaining_seconds(self) -> float | None:
        """Return seconds remaining until the scanner deadline, if configured."""
        if self.deadline_perf is None:
            return None
        return max(0.0, self.deadline_perf - time.perf_counter())

    def raise_if_cancelled(self) -> None:
        """Raise when cancellation or an expired deadline has been observed."""
        if self.is_cancelled():
            raise ScannerDeadlineExceededError(self.reason)

    def wait_for_cancellation(self, timeout_seconds: float) -> bool:
        """Wait for cancellation without an uninterrupted sleep."""
        if self.is_cancelled():
            return True
        return self._cancelled.wait(max(0.0, timeout_seconds)) or self.is_cancelled()
