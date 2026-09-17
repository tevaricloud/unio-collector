from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.s3.coverage_notes import S3BucketCoverageNoteBuilder
    from unio_collector.aws.s3.identity import S3BucketIdentity
    from unio_collector.aws.s3.lifecycle.record import S3BucketLifecycleRecord


@dataclass(frozen=True)
class S3MultipartBucketSelector:
    """Select a deterministic neutral operational multipart population.

    The historical selector identity and parameters remain accepted for
    compatibility, but lifecycle and storage policy never affect collection.
    """

    note_builder: S3BucketCoverageNoteBuilder

    def filter_buckets_with_abort_rule(  # noqa: D102
        self,
        buckets: list[S3BucketIdentity],
        *,
        lifecycle_records: list[S3BucketLifecycleRecord] | None,
        skip_buckets_with_abort_incomplete_rule: bool,
    ) -> tuple[list[S3BucketIdentity], list[dict[str, Any]]]:
        del lifecycle_records, skip_buckets_with_abort_incomplete_rule
        return sorted(buckets, key=lambda bucket: bucket.bucket_name), []

    def limit_buckets(  # noqa: D102
        self,
        buckets: list[S3BucketIdentity],
        *,
        max_multipart_buckets: int,
        lifecycle_records: list[S3BucketLifecycleRecord] | None,
        multipart_bucket_selection_mode: object,
    ) -> tuple[list[S3BucketIdentity], list[dict[str, Any]]]:
        del lifecycle_records, multipart_bucket_selection_mode
        ordered = sorted(buckets, key=lambda bucket: bucket.bucket_name)
        if max_multipart_buckets <= 0 or len(ordered) <= max_multipart_buckets:
            return ordered, []
        limited = ordered[:max_multipart_buckets]
        return limited, [
            self.note_builder.build_multipart_bucket_cap_note(
                max_multipart_buckets=max_multipart_buckets,
                selection_mode="bucket-name",
                selection_context_available=False,
                selected_bucket_count=len(ordered),
                evaluated_bucket_count=len(limited),
            ),
        ]

    def order_buckets(  # noqa: D102
        self,
        buckets: list[S3BucketIdentity],
        *,
        lifecycle_records: list[S3BucketLifecycleRecord] | None,
        selection_mode: str,
    ) -> list[S3BucketIdentity]:
        del lifecycle_records, selection_mode
        return sorted(buckets, key=lambda bucket: bucket.bucket_name)


__all__ = ["S3MultipartBucketSelector"]
