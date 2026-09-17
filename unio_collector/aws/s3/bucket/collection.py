from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.s3.lifecycle.collection_summary import (
        S3LifecycleCollectionSummary,
    )
    from unio_collector.aws.s3.lifecycle.record import S3BucketLifecycleRecord
    from unio_collector.aws.s3.multipart.bucket_context import S3MultipartBucketContext
    from unio_collector.aws.s3.multipart.collection_summary import (
        S3MultipartCollectionSummary,
    )
    from unio_collector.aws.s3.multipart.upload import S3MultipartUploadRecord


@dataclass(frozen=True)
class S3BucketCollectionResult:  # noqa: D101
    lifecycle_records: list[S3BucketLifecycleRecord] = field(default_factory=list)
    multipart_records: list[S3MultipartUploadRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    coverage_notes: list[dict[str, Any]] = field(default_factory=list)
    discovered_bucket_count: int = 0
    selected_bucket_count: int = 0
    evaluated_bucket_count: int = 0
    lifecycle_collection_summary: S3LifecycleCollectionSummary | None = None
    multipart_collection_summary: S3MultipartCollectionSummary | None = None
    multipart_bucket_contexts: list[S3MultipartBucketContext] = field(
        default_factory=list,
    )
