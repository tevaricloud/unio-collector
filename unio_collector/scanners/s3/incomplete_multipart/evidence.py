from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.s3 import (
        S3MultipartBucketContext,
        S3MultipartCollectionSummary,
        S3MultipartUploadRecord,
    )


@dataclass(frozen=True)
class S3MultipartEvidence:  # noqa: D101
    records: list[S3MultipartUploadRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    collection_summary: S3MultipartCollectionSummary | None = None
    bucket_contexts: list[S3MultipartBucketContext] = field(default_factory=list)
    selection_policy_applied: bool = True
    historical_skip_abort_rule_buckets: bool = True
    historical_selection_mode: str = "inventory-order"
    historical_bucket_limit: int = 0
