from __future__ import annotations  # noqa: D100

from unio_collector.aws.cache.failure.category import CacheFailureCategory
from unio_collector.aws.cache.failure.decision import CacheFailureDecision
from unio_collector.aws.cache.failure.retention import CacheFailureRetention


class DefaultCacheFailureClassifier:
    """Treat unknown loader failures as retryable internal errors."""

    def classify(self, error: BaseException) -> CacheFailureDecision:
        """Return the provider-neutral default failure decision."""
        return CacheFailureDecision(
            category=CacheFailureCategory.INTERNAL_LOADER_ERROR,
            retention=CacheFailureRetention.EVICT,
            error_code=error.__class__.__name__,
        )
