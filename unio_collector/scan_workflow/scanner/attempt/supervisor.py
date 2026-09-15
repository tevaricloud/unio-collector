from __future__ import annotations  # noqa: D100

import queue
import threading
import time
from typing import TYPE_CHECKING, TypeVar

from unio_collector.runtime_diagnostics.exception_record import sanitize_diagnostic_text
from unio_collector.scan_workflow.scanner.attempt.outcome_reason import (
    ScannerAttemptOutcomeReason,
)
from unio_collector.scan_workflow.scanner.attempt.result import ScannerAttemptRunResult
from unio_collector.scan_workflow.scanner.runtime.cancellation_error import (
    ScannerDeadlineExceededError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext

T = TypeVar("T")
_WAIT_INTERVAL_SECONDS = 0.1


class ScannerAttemptSupervisor[T]:
    """Bound physically live scanner workers while preserving soft timeouts."""

    def __init__(self, max_live_attempts: int) -> None:
        """Create a supervisor with a fixed physical worker bound."""
        if max_live_attempts <= 0:
            msg = "Scanner attempt supervisor capacity must be positive."
            raise ValueError(msg)
        self._capacity = threading.BoundedSemaphore(max_live_attempts)
        self._active_attempt_ids: set[str] = set()
        self._active_lock = threading.Lock()

    @property
    def active_attempt_count(self) -> int:
        """Return the number of physically live scanner workers."""
        with self._active_lock:
            return len(self._active_attempt_ids)

    def run(
        self,
        attempt: ScannerAttemptContext,
        func: Callable[[], T],
    ) -> ScannerAttemptRunResult[T]:
        """Run one attempt or time out before allocating another worker."""
        started = time.perf_counter()
        if not self._acquire_capacity(attempt):
            return self._timeout_result(attempt, started)

        results: queue.Queue[tuple[T | None, str | None, str | None]] = queue.Queue(
            maxsize=1,
        )
        thread = threading.Thread(
            target=self._execute,
            args=(attempt, func, results),
            name=f"unio-collector-scanner-{attempt.scanner_id}-{attempt.attempt_id[:8]}",
            daemon=True,
        )
        with self._active_lock:
            self._active_attempt_ids.add(attempt.attempt_id)
        thread.start()
        remaining = attempt.time_remaining_seconds()
        thread.join(remaining)
        if thread.is_alive():
            attempt.mark_timed_out(
                ScannerAttemptOutcomeReason.SCHEDULER_TIMEOUT,
                message="Scanner execution timed out.",
            )
            return self._timeout_result(attempt, started)

        duration_ms = int((time.perf_counter() - started) * 1000)
        try:
            value, error, exception_type = results.get_nowait()
        except queue.Empty:
            return ScannerAttemptRunResult(
                attempt=attempt,
                outcome_reason=ScannerAttemptOutcomeReason.UNHANDLED_WORKER_FAILURE,
                duration_ms=duration_ms,
                error="Scanner attempt finished without returning a result.",
            )
        return ScannerAttemptRunResult(
            attempt=attempt,
            outcome_reason=attempt.outcome_reason,
            duration_ms=duration_ms,
            value=value,
            error=error,
            exception_type=exception_type,
        )

    def _acquire_capacity(self, attempt: ScannerAttemptContext) -> bool:
        while True:
            remaining = attempt.time_remaining_seconds()
            if remaining is not None and remaining <= 0:
                attempt.mark_timed_out(
                    ScannerAttemptOutcomeReason.DEADLINE_EXPIRED,
                    message="Scanner deadline expired before a worker became available.",
                )
                attempt.close()
                return False
            if attempt.cancellation_token.is_cancelled():
                attempt.cancel(attempt.cancellation_token.reason)
                attempt.close()
                return False
            interval = _WAIT_INTERVAL_SECONDS if remaining is None else min(_WAIT_INTERVAL_SECONDS, remaining)
            if self._capacity.acquire(timeout=interval):
                if attempt.cancellation_token.is_cancelled() or attempt.time_remaining_seconds() == 0:
                    self._capacity.release()
                    if attempt.time_remaining_seconds() == 0:
                        attempt.mark_timed_out(
                            ScannerAttemptOutcomeReason.DEADLINE_EXPIRED,
                            message="Scanner deadline expired before a worker could start.",
                        )
                    else:
                        attempt.cancel(attempt.cancellation_token.reason)
                    attempt.close()
                    return False
                return True
            if attempt.wait_for_cancellation(0):
                attempt.mark_timed_out(
                    ScannerAttemptOutcomeReason.DEADLINE_EXPIRED,
                    message="Scanner deadline expired while waiting for worker capacity.",
                )
                attempt.close()
                return False

    def _execute(
        self,
        attempt: ScannerAttemptContext,
        func: Callable[[], T],
        results: queue.Queue[tuple[T | None, str | None, str | None]],
    ) -> None:
        value: T | None = None
        error: str | None = None
        exception_type: str | None = None
        try:
            self._require_started(attempt)
            value = func()
            attempt.require_commit_authority()
            status = getattr(value, "status", None)
            if status == "permission_denied":
                attempt.mark_failed(ScannerAttemptOutcomeReason.PERMISSION_FAILURE)
            elif status == "failed":
                attempt.mark_failed(ScannerAttemptOutcomeReason.SCANNER_FAILURE)
            else:
                attempt.mark_completed()
        except ScannerDeadlineExceededError as exc:
            error = sanitize_diagnostic_text(exc)
            exception_type = type(exc).__name__
            if attempt.has_commit_authority():
                attempt.mark_timed_out(
                    ScannerAttemptOutcomeReason.DEADLINE_EXPIRED,
                    message=str(exc),
                )
        except Exception as exc:  # noqa: BLE001
            error = sanitize_diagnostic_text(exc)
            exception_type = type(exc).__name__
            if attempt.has_commit_authority():
                attempt.mark_failed(
                    ScannerAttemptOutcomeReason.UNHANDLED_WORKER_FAILURE,
                )
        finally:
            results.put((value, error, exception_type))
            if attempt.lifecycle_state.value != "closed":
                attempt.close()
            with self._active_lock:
                self._active_attempt_ids.discard(attempt.attempt_id)
            self._capacity.release()

    def _require_started(self, attempt: ScannerAttemptContext) -> None:
        if attempt.start():
            return
        raise ScannerDeadlineExceededError(attempt.cancellation_token.reason)

    def _timeout_result(
        self,
        attempt: ScannerAttemptContext,
        started: float,
    ) -> ScannerAttemptRunResult[T]:
        return ScannerAttemptRunResult(
            attempt=attempt,
            outcome_reason=attempt.outcome_reason,
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=attempt.cancellation_token.reason,
            exception_type=ScannerDeadlineExceededError.__name__,
        )
