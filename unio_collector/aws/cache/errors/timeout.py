from __future__ import annotations  # noqa: D100

from unio_collector.aws.cache.errors.base import AwsScanCacheError


class AwsScanCacheWaitTimeoutError(AwsScanCacheError):
    """Raised when a bounded waiter cannot claim a replacement generation."""
