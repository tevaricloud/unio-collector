from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.s3.identity import S3BucketIdentity


@dataclass(frozen=True)
class S3RegionalBucketMetadataResult:  # noqa: D101
    identities: list[S3BucketIdentity] = field(default_factory=list)
    regional_lookup_complete: bool = False
