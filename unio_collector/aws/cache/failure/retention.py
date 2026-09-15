from __future__ import annotations  # noqa: D100

from enum import StrEnum


class CacheFailureRetention(StrEnum):
    """Whether a normalized failed load remains reusable in this scan."""

    RETAIN = "retain"
    EVICT = "evict"
