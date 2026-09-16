from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class S3BucketStorageMetric:  # noqa: D101
    bucket_name: str
    size_bytes: int | None = None
    object_count: int | None = None
    metric_collected: bool = False
    limitation: str | None = None

    @property
    def has_known_storage(self) -> bool:  # noqa: D102
        return self.size_bytes is not None or self.object_count is not None

    @property
    def is_known_empty(self) -> bool:  # noqa: D102
        return self.object_count is not None and self.object_count <= 0 and (self.size_bytes is None or self.size_bytes <= 0)
