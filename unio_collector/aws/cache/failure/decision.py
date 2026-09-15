from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cache.failure.category import CacheFailureCategory
    from unio_collector.aws.cache.failure.retention import CacheFailureRetention


@dataclass(frozen=True)
class CacheFailureDecision:
    """Classification and retention decision for one failed load."""

    category: CacheFailureCategory
    retention: CacheFailureRetention
    error_code: str | None = None
