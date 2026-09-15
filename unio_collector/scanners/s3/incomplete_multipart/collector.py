from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.s3_bucket_scanner import BaseS3BucketCostScanner
from unio_collector.scanners.s3.cost_context import add_s3_cost_context
from unio_collector.scanners.s3.incomplete_multipart.evidence import S3MultipartEvidence
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class S3IncompleteMultipartReviewCollector(BaseS3BucketCostScanner):
    """Collect provider evidence for s3-incomplete-multipart-review."""

    def collect(self, context: ScannerContext) -> S3MultipartEvidence:  # noqa: D102
        skip_abort = self._get_skip_abort_rule_buckets(context)
        selection_mode = self._get_multipart_bucket_selection_mode(context)
        bucket_limit = self._get_multipart_bucket_cap(context)
        collection = context.s3.collect_multipart_records(
            max_buckets=self._get_bucket_cap(context),
            max_bucket_workers=self._get_bucket_worker_count(context),
            max_multipart_uploads_per_bucket=self._get_upload_cap(context),
            max_multipart_buckets=bucket_limit,
            multipart_bucket_selection_mode=selection_mode,
            skip_buckets_with_abort_incomplete_rule=skip_abort,
            lifecycle_collection_options=(
                self._get_lifecycle_collection_options(
                    context,
                    scanner_id="s3-lifecycle-cost-review",
                )
            ),
        )
        self._record_collection_context(
            context,
            warnings=collection.warnings,
            coverage_notes=collection.coverage_notes,
        )
        return S3MultipartEvidence(
            records=add_s3_cost_context(collection.multipart_records, context),
            regions=collection.regions,
            collection_summary=collection.multipart_collection_summary,
            bucket_contexts=collection.multipart_bucket_contexts,
            selection_policy_applied=False,
            historical_skip_abort_rule_buckets=skip_abort,
            historical_selection_mode=selection_mode,
            historical_bucket_limit=bucket_limit,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="S3IncompleteMultipartReviewScanner",
            implementation_module="unio_collector.scanners.s3.incomplete_multipart.scanner",
        )
