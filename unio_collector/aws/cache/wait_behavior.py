from __future__ import annotations  # noqa: D100

from enum import StrEnum


class CacheWaitTimeoutBehavior(StrEnum):
    """Action taken when a cache waiter exhausts its bounded wait."""

    REPLACE_AND_RETRY = "replace_and_retry"
    RAISE = "raise"
