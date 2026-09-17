from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class S3MultipartBucketContext:  # noqa: D101
    bucket_name: str
    lifecycle_context_known: bool = False
    abort_incomplete_upload_rule: bool | None = None
    storage_metric_known: bool = False
    object_count: int | None = None
    size_bytes: int | None = None

    def __post_init__(self) -> None:  # noqa: D105
        object.__setattr__(self, "bucket_name", self.bucket_name.strip())
        if not self.lifecycle_context_known:
            object.__setattr__(self, "abort_incomplete_upload_rule", None)
        if not self.storage_metric_known:
            object.__setattr__(self, "object_count", None)
            object.__setattr__(self, "size_bytes", None)
        else:
            for name in ("object_count", "size_bytes"):
                value = getattr(self, name)
                if value is not None:
                    object.__setattr__(self, name, max(0, int(value)))


__all__ = ["S3MultipartBucketContext"]
