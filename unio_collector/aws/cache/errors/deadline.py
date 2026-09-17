from __future__ import annotations  # noqa: D100

from unio_collector.aws.cache.errors.base import AwsScanCacheError


class AwsScanCacheDeadlineExceededError(AwsScanCacheError):
    """Raised when a cache access reaches its monotonic deadline."""
