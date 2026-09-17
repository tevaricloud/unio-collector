from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cache.types import CacheAccessStatus


@dataclass
class AwsScanCacheConsumerStats:  # noqa: D101
    loaded_count: int = 0
    hit_count: int = 0
    wait_count: int = 0
    error_count: int = 0
    namespaces: set[str] = field(default_factory=set)

    def record_status(self, namespace: str, status: CacheAccessStatus) -> None:  # noqa: D102
        self.namespaces.add(namespace)
        if status == "loaded":
            self.loaded_count += 1
        elif status == "hit":
            self.hit_count += 1
        elif status == "waited":
            self.wait_count += 1

    def record_error(self, namespace: str) -> None:  # noqa: D102
        self.namespaces.add(namespace)
        self.error_count += 1

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "loaded_count": self.loaded_count,
            "hit_count": self.hit_count,
            "wait_count": self.wait_count,
            "reuse_count": self.hit_count + self.wait_count,
            "error_count": self.error_count,
            "namespaces": sorted(self.namespaces),
        }
