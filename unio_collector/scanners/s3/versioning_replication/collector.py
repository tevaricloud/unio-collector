from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.s3_bucket_scanner import BaseS3BucketCostScanner
from unio_collector.scanners.s3.cost_context import add_s3_cost_context
from unio_collector.scanners.s3.lifecycle.evidence import S3LifecycleEvidence
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class S3VersioningAndReplicationReviewCollector(BaseS3BucketCostScanner):
    """Collect provider evidence for s3-versioning-and-replication-review."""

    def collect(self, context: ScannerContext) -> S3LifecycleEvidence:  # noqa: D102
        options = self._get_lifecycle_collection_options(context)
        collection = context.s3.collect_lifecycle_records(
            max_buckets=self._get_bucket_cap(context),
            max_bucket_workers=self._get_bucket_worker_count(context),
            collection_options=options,
        )
        self._record_collection_context(
            context,
            warnings=collection.warnings,
            coverage_notes=collection.coverage_notes,
        )
        return S3LifecycleEvidence(
            records=add_s3_cost_context(collection.lifecycle_records, context),
            regions=collection.regions,
            collection_summary=collection.lifecycle_collection_summary,
            selection_policy_applied=False,
            historical_selection_mode=options.lifecycle_detail_mode,
            historical_bucket_limit=options.prioritized_lifecycle_bucket_count,
            historical_include_metric_unknown=(options.include_lifecycle_metric_unknown_buckets),
            historical_conditional_versioning=(options.conditional_versioning_collection),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="S3VersioningAndReplicationReviewScanner",
            implementation_module="unio_collector.scanners.s3.versioning_replication.scanner",
        )
