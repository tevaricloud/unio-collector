from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.cache.failure.decision import CacheFailureDecision


class CacheFailureClassifier(Protocol):
    """Caller-owned policy for classifying loader failures."""

    def classify(self, error: BaseException) -> CacheFailureDecision:
        """Classify a loader failure without retaining the exception object."""
        ...
