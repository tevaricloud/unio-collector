from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.s3.identity import S3BucketIdentity


@dataclass(frozen=True)
class S3BucketIndexResult:  # noqa: D101
    buckets: list[S3BucketIdentity] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    discovered_bucket_count: int = 0
    selected_bucket_count: int = 0
    warnings: list[str] = field(default_factory=list)
