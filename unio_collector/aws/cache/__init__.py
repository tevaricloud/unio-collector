from __future__ import annotations  # noqa: D104

from unio_collector.aws.cache.access import AwsScanCacheAccess
from unio_collector.aws.cache.cancellation import CacheCancellationToken
from unio_collector.aws.cache.consumer_stats import AwsScanCacheConsumerStats
from unio_collector.aws.cache.errors import (
    AwsScanCacheCancelledError,
    AwsScanCacheDeadlineExceededError,
    AwsScanCacheError,
    AwsScanCacheGenerationSupersededError,
    AwsScanCacheLoadError,
    AwsScanCacheWaitTimeoutError,
)
from unio_collector.aws.cache.failure import (
    CacheFailureCategory,
    CacheFailureClassifier,
    CacheFailureDecision,
    CacheFailureRetention,
    CacheFailureSnapshot,
    DefaultCacheFailureClassifier,
)
from unio_collector.aws.cache.key import AwsScanCacheKey
from unio_collector.aws.cache.policy import AwsScanCacheAccessPolicy
from unio_collector.aws.cache.scan import AwsScanCache
from unio_collector.aws.cache.stats import AwsScanCacheStats
from unio_collector.aws.cache.types import (
    CacheAccessStatus,
)
from unio_collector.aws.cache.wait_behavior import CacheWaitTimeoutBehavior

__all__ = [
    "AwsScanCache",
    "AwsScanCacheAccess",
    "AwsScanCacheAccessPolicy",
    "AwsScanCacheCancelledError",
    "AwsScanCacheConsumerStats",
    "AwsScanCacheDeadlineExceededError",
    "AwsScanCacheError",
    "AwsScanCacheGenerationSupersededError",
    "AwsScanCacheKey",
    "AwsScanCacheLoadError",
    "AwsScanCacheStats",
    "AwsScanCacheWaitTimeoutError",
    "CacheAccessStatus",
    "CacheCancellationToken",
    "CacheFailureCategory",
    "CacheFailureClassifier",
    "CacheFailureDecision",
    "CacheFailureRetention",
    "CacheFailureSnapshot",
    "CacheWaitTimeoutBehavior",
    "DefaultCacheFailureClassifier",
]
