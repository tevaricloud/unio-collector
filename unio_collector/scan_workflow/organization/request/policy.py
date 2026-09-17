from __future__ import annotations

# ruff: noqa: D100
from dataclasses import dataclass


@dataclass(frozen=True)
class OrganizationExecutionPolicy:
    """Bound account concurrency, timeouts, retries, and cancellation."""

    max_concurrency: int = 2
    account_timeout_seconds: int = 3300
    max_attempts: int = 2
    retry_backoff_seconds: float = 2
    cancellation_grace_seconds: int = 30
