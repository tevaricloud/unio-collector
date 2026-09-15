from __future__ import annotations  # noqa: D100

from unio_collector.aws.cache.errors.base import AwsScanCacheError


class AwsScanCacheGenerationSupersededError(AwsScanCacheError):
    """Raised when a late loader no longer owns publication authority."""
