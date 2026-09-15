from __future__ import annotations  # noqa: D100

from enum import StrEnum


class ScannerAttemptLifecycleState(StrEnum):
    """Internal lifecycle states for one scheduled scanner attempt."""

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    CLOSED = "closed"
