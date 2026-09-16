from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from unio_collector.aws.cache.failure import DefaultCacheFailureClassifier
from unio_collector.aws.cache.wait_behavior import CacheWaitTimeoutBehavior

if TYPE_CHECKING:
    from unio_collector.aws.cache.cancellation import CacheCancellationToken
    from unio_collector.aws.cache.failure import CacheFailureClassifier

DEFAULT_CACHE_MAX_WAIT_SECONDS = 30.0


@dataclass(frozen=True)
class AwsScanCacheAccessPolicy:
    """Bounded wait and loader-failure policy for one cache access."""

    cancellation_token: CacheCancellationToken | None = None
    deadline_monotonic: float | None = None
    max_wait_seconds: float = DEFAULT_CACHE_MAX_WAIT_SECONDS
    consumer_id: str | None = None
    attempt_id: str | None = None
    wait_timeout_behavior: CacheWaitTimeoutBehavior = CacheWaitTimeoutBehavior.REPLACE_AND_RETRY
    failure_classifier: CacheFailureClassifier = field(
        default_factory=DefaultCacheFailureClassifier,
    )

    def __post_init__(self) -> None:
        """Reject policies that could restore an unbounded event wait."""
        if self.max_wait_seconds <= 0:
            message = "Cache max_wait_seconds must be greater than zero."
            raise ValueError(message)
