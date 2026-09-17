from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.s3.public_access.bucket_record import (
        S3PublicAccessBucketRecord,
    )


@dataclass(frozen=True)
class S3PublicAccessEvidence:  # noqa: D101
    account_public_access_block: dict[str, bool] | None = None
    account_public_access_block_status: str = "unknown"
    account_public_access_block_error_code: str | None = None
    buckets: tuple[S3PublicAccessBucketRecord, ...] = ()
    warnings: tuple[str, ...] = ()
    account_id: str = "unknown-account"
