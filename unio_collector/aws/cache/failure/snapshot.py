from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cache.failure.category import CacheFailureCategory
    from unio_collector.aws.cache.failure.decision import CacheFailureDecision


@dataclass(frozen=True)
class CacheFailureSnapshot:
    """Traceback-free representation of a failed loader generation."""

    category: CacheFailureCategory
    error_type: str
    error_code: str

    @classmethod
    def from_error(
        cls,
        error: BaseException,
        decision: CacheFailureDecision,
    ) -> CacheFailureSnapshot:
        """Normalize an exception into retained cache-safe metadata."""
        return cls(
            category=decision.category,
            error_type=error.__class__.__name__,
            error_code=decision.error_code or error.__class__.__name__,
        )
