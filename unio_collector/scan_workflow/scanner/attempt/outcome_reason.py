from __future__ import annotations  # noqa: D100

from enum import StrEnum


class ScannerAttemptOutcomeReason(StrEnum):
    """Typed internal reason for the authoritative attempt outcome."""

    NONE = "none"
    SUCCESS = "success"
    SCANNER_FAILURE = "scanner_failure"
    PERMISSION_FAILURE = "permission_failure"
    EXPLICIT_CANCELLATION = "explicit_cancellation"
    DEADLINE_EXPIRED = "deadline_expired"
    SCHEDULER_TIMEOUT = "scheduler_timeout"
    UNHANDLED_WORKER_FAILURE = "unhandled_worker_failure"
