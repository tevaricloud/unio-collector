from __future__ import annotations  # noqa: D100

import threading
import time
import uuid
from datetime import UTC, datetime

from unio_collector.scan_workflow.scanner.attempt.lifecycle_state import (
    ScannerAttemptLifecycleState,
)
from unio_collector.scan_workflow.scanner.attempt.outcome_reason import (
    ScannerAttemptOutcomeReason,
)
from unio_collector.scan_workflow.scanner.runtime.cancellation import (
    ScannerCancellationToken,
)
from unio_collector.scan_workflow.scanner.runtime.cancellation_error import (
    ScannerDeadlineExceededError,
)

_TERMINAL_STATES = {
    ScannerAttemptLifecycleState.COMPLETED,
    ScannerAttemptLifecycleState.FAILED,
    ScannerAttemptLifecycleState.CANCELLED,
    ScannerAttemptLifecycleState.TIMED_OUT,
}


class ScannerAttemptContext:
    """Thread-safe lifecycle and commit authority for one scanner attempt."""

    def __init__(
        self,
        *,
        scanner_id: str,
        timeout_seconds: float | None,
        attempt_id: str | None = None,
    ) -> None:
        """Create an attempt with a fresh or supplied stable identifier."""
        self.attempt_id = attempt_id or str(uuid.uuid4())
        self.scanner_id = scanner_id
        self.cancellation_token = ScannerCancellationToken.from_timeout_seconds(
            timeout_seconds,
        )
        self.deadline_monotonic = self.cancellation_token.deadline_perf
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None
        self.closed_at: datetime | None = None
        self._state = ScannerAttemptLifecycleState.CREATED
        self._outcome_reason = ScannerAttemptOutcomeReason.NONE
        self._commit_authority = False
        self._lock = threading.RLock()

    @property
    def lifecycle_state(self) -> ScannerAttemptLifecycleState:
        """Return the current lifecycle state."""
        with self._lock:
            return self._state

    @property
    def outcome_reason(self) -> ScannerAttemptOutcomeReason:
        """Return the current typed outcome reason."""
        with self._lock:
            return self._outcome_reason

    def start(self) -> bool:
        """Enter running state unless the deadline has already expired."""
        with self._lock:
            self._refresh_deadline_locked()
            if self._state is not ScannerAttemptLifecycleState.CREATED:
                return False
            self._state = ScannerAttemptLifecycleState.RUNNING
            self._commit_authority = True
            self.started_at = datetime.now(UTC)
            return True

    def mark_completed(self) -> None:
        """Record successful physical completion while authority is active."""
        self._finish(
            ScannerAttemptLifecycleState.COMPLETED,
            ScannerAttemptOutcomeReason.SUCCESS,
        )

    def mark_failed(self, reason: ScannerAttemptOutcomeReason) -> None:
        """Record a scanner or worker failure."""
        if reason not in {
            ScannerAttemptOutcomeReason.SCANNER_FAILURE,
            ScannerAttemptOutcomeReason.PERMISSION_FAILURE,
            ScannerAttemptOutcomeReason.UNHANDLED_WORKER_FAILURE,
        }:
            msg = f"Invalid scanner attempt failure reason: {reason}."
            raise ValueError(msg)
        self._finish(ScannerAttemptLifecycleState.FAILED, reason)

    def cancel(self, reason: str = "Scanner execution was cancelled.") -> None:
        """Revoke authority and record explicit cancellation."""
        self.cancellation_token.cancel(reason)
        self._finish(
            ScannerAttemptLifecycleState.CANCELLED,
            ScannerAttemptOutcomeReason.EXPLICIT_CANCELLATION,
        )

    def mark_timed_out(
        self,
        reason: ScannerAttemptOutcomeReason,
        *,
        message: str,
    ) -> None:
        """Revoke authority and record deadline or scheduler timeout."""
        if reason not in {
            ScannerAttemptOutcomeReason.DEADLINE_EXPIRED,
            ScannerAttemptOutcomeReason.SCHEDULER_TIMEOUT,
        }:
            msg = f"Invalid scanner attempt timeout reason: {reason}."
            raise ValueError(msg)
        self.cancellation_token.cancel(message)
        self._finish(ScannerAttemptLifecycleState.TIMED_OUT, reason)

    def close(self) -> None:
        """Close a terminal attempt after its physical worker exits."""
        with self._lock:
            if self._state is ScannerAttemptLifecycleState.CLOSED:
                return
            if self._state not in _TERMINAL_STATES:
                msg = f"Cannot close scanner attempt from {self._state.value}."
                raise RuntimeError(msg)
            self._state = ScannerAttemptLifecycleState.CLOSED
            self._commit_authority = False
            self.closed_at = datetime.now(UTC)

    def has_commit_authority(self) -> bool:
        """Return whether scanner state may still be committed."""
        with self._lock:
            self._refresh_deadline_locked()
            return self._commit_authority and self._state is ScannerAttemptLifecycleState.RUNNING

    def require_commit_authority(self) -> None:
        """Raise when scanner state may no longer be consumed."""
        if self.has_commit_authority():
            return
        raise ScannerDeadlineExceededError(self.cancellation_token.reason)

    def raise_if_cancelled(self) -> None:
        """Raise when cancellation or deadline expiry has revoked authority."""
        self.require_commit_authority()

    def time_remaining_seconds(self) -> float | None:
        """Return remaining monotonic deadline budget."""
        return self.cancellation_token.time_remaining_seconds()

    def wait_for_cancellation(self, timeout_seconds: float) -> bool:
        """Wait for cancellation without busy polling."""
        return self.cancellation_token.wait_for_cancellation(timeout_seconds)

    def get_completion_classification(self) -> str:
        """Classify a returned operation as committed or late."""
        return "committed" if self.has_commit_authority() else "late"

    def get_outcome_reason(self) -> str:
        """Return the outcome reason value for audit metadata."""
        return self.outcome_reason.value

    def _finish(
        self,
        state: ScannerAttemptLifecycleState,
        reason: ScannerAttemptOutcomeReason,
    ) -> None:
        with self._lock:
            if self._state in _TERMINAL_STATES or self._state is ScannerAttemptLifecycleState.CLOSED:
                return
            if self._state not in {
                ScannerAttemptLifecycleState.CREATED,
                ScannerAttemptLifecycleState.RUNNING,
            }:
                msg = f"Invalid scanner attempt transition from {self._state.value}."
                raise RuntimeError(msg)
            if (
                state
                in {
                    ScannerAttemptLifecycleState.COMPLETED,
                    ScannerAttemptLifecycleState.FAILED,
                }
                and self._state is not ScannerAttemptLifecycleState.RUNNING
            ):
                msg = f"Cannot mark an unstarted scanner attempt as {state.value}."
                raise RuntimeError(msg)
            self._state = state
            self._outcome_reason = reason
            self._commit_authority = False
            self.completed_at = datetime.now(UTC)

    def _refresh_deadline_locked(self) -> None:
        if self._state not in {
            ScannerAttemptLifecycleState.CREATED,
            ScannerAttemptLifecycleState.RUNNING,
        }:
            return
        deadline_expired = self.deadline_monotonic is not None and time.perf_counter() >= self.deadline_monotonic
        if not deadline_expired and not self.cancellation_token.is_cancelled():
            return
        if deadline_expired:
            self.cancellation_token.cancel(
                "Scanner deadline expired before this work could complete.",
            )
            self._state = ScannerAttemptLifecycleState.TIMED_OUT
            self._outcome_reason = ScannerAttemptOutcomeReason.DEADLINE_EXPIRED
        else:
            self._state = ScannerAttemptLifecycleState.CANCELLED
            self._outcome_reason = ScannerAttemptOutcomeReason.EXPLICIT_CANCELLATION
        self._commit_authority = False
        self.completed_at = datetime.now(UTC)
