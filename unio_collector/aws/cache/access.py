from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cache.key import AwsScanCacheKey
    from unio_collector.aws.cache.types import CacheAccessStatus


@dataclass(frozen=True)
class AwsScanCacheAccess[T]:  # noqa: D101
    value: T
    status: CacheAccessStatus
    key: AwsScanCacheKey

    def is_reused(self) -> bool:  # noqa: D102
        return self.status in {"hit", "waited"}
