"""Spawn-process supervision for physically bounded account attempts."""

from __future__ import annotations

import multiprocessing
import threading
import time
from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.organization.attempt.cancelled_error import (
    OrganizationAttemptCancelledError,
)
from unio_collector.scan_workflow.organization.attempt.collect_worker import run_collect_attempt
from unio_collector.scan_workflow.organization.attempt.timeout_error import (
    OrganizationAttemptTimeoutError,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from multiprocessing.connection import Connection

    from unio_collector.scan_workflow.organization.attempt.request import (
        OrganizationAttemptRequest,
    )
    from unio_collector.scan_workflow.organization.attempt.result import (
        OrganizationAttemptResult,
    )


class OrganizationAttemptSupervisor:
    """Own spawned children and retain exclusive artifact-promotion authority."""

    def __init__(
        self,
        *,
        worker: Callable[[Any, Connection], None] = run_collect_attempt,
    ) -> None:
        """Create an empty cross-thread child registry."""
        self._context = multiprocessing.get_context("spawn")
        self._lock = threading.RLock()
        self._active: dict[int, Any] = {}
        self._cancelled = False
        self._worker = worker

    def run(
        self,
        request: OrganizationAttemptRequest[object],
        *,
        timeout_seconds: float,
        cancellation_grace_seconds: float,
    ) -> OrganizationAttemptResult:
        """Return only a timely child result, terminating late execution."""
        parent_connection, child_connection = self._context.Pipe(duplex=False)
        process = self._context.Process(
            target=self._worker,
            args=(request, child_connection),
            name=f"unio-collector-org-{request.account.alias}-{request.attempt}",
        )
        process.start()
        child_connection.close()
        with self._lock:
            self._active[process.pid or id(process)] = process
            cancelled = self._cancelled
        started = time.monotonic()
        try:
            while not cancelled and time.monotonic() - started < timeout_seconds:
                if parent_connection.poll(0.05):
                    payload = parent_connection.recv()
                    process.join(timeout=cancellation_grace_seconds)
                    if process.is_alive():
                        self._stop(process, cancellation_grace_seconds)
                        message = "Organization attempt did not exit after returning a result."
                        raise OrganizationAttemptTimeoutError(message)
                    if isinstance(payload, BaseException):
                        raise payload
                    return payload
                if not process.is_alive():
                    process.join()
                    with self._lock:
                        cancelled = self._cancelled
                    if cancelled:
                        message = "Organization attempt authority was revoked by user cancellation."
                        raise OrganizationAttemptCancelledError(message)
                    message = f"Organization attempt exited without a result (exit code {process.exitcode})."
                    raise RuntimeError(message)
                with self._lock:
                    cancelled = self._cancelled
            self._stop(process, cancellation_grace_seconds)
            if cancelled:
                message = "Organization attempt authority was revoked by user cancellation."
                raise OrganizationAttemptCancelledError(message)
            message = "Organization account execution exceeded its configured deadline."
            raise OrganizationAttemptTimeoutError(message)
        finally:
            parent_connection.close()
            with self._lock:
                self._active.pop(process.pid or id(process), None)

    def cancel_all(self, *, cancellation_grace_seconds: float) -> None:
        """Revoke every active attempt and wait for physical process exit."""
        with self._lock:
            self._cancelled = True
            processes = tuple(self._active.values())
        for process in processes:
            self._stop(process, cancellation_grace_seconds)

    def _stop(
        self,
        process: Any,  # noqa: ANN401
        cancellation_grace_seconds: float,
    ) -> None:
        if process.is_alive():
            process.terminate()
            process.join(timeout=cancellation_grace_seconds)
        if process.is_alive():
            process.kill()
            process.join()
        else:
            process.join()


__all__ = [
    "OrganizationAttemptSupervisor",
]
