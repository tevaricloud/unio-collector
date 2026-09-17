from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass
class AwsScanCacheStats:  # noqa: D101
    request_count: int = 0
    hit_count: int = 0
    miss_count: int = 0
    wait_count: int = 0
    error_count: int = 0
    key_count: int = 0

    def convert_to_dict(self) -> dict[str, int]:  # noqa: D102
        return {
            "request_count": self.request_count,
            "hit_count": self.hit_count,
            "miss_count": self.miss_count,
            "wait_count": self.wait_count,
            "error_count": self.error_count,
            "key_count": self.key_count,
        }
