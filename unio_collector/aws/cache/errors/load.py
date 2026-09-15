from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.cache.errors.base import AwsScanCacheError

if TYPE_CHECKING:
    from unio_collector.aws.cache.failure.snapshot import CacheFailureSnapshot


class AwsScanCacheLoadError(AwsScanCacheError):
    """Replay a normalized loader failure without retaining its exception."""

    def __init__(self, snapshot: CacheFailureSnapshot) -> None:  # noqa: D107
        self.cache_failure_category = snapshot.category.value
        self.original_error_type = snapshot.error_type
        self.aws_error_code = snapshot.error_code
        message = f"Cached loader failure ({snapshot.error_code}; {snapshot.error_type})."
        super().__init__(message)
