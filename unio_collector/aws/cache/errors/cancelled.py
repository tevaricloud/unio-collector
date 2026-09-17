from __future__ import annotations  # noqa: D100

from unio_collector.aws.cache.errors.base import AwsScanCacheError


class AwsScanCacheCancelledError(AwsScanCacheError):
    """Raised when a cache access observes caller cancellation."""
