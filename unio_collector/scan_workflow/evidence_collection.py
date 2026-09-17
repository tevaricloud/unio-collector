from __future__ import annotations  # noqa: D100

from unio_collector.scan_workflow.evidence import (
    CloudWatchEvidenceMixin,
    CostExplorerEvidenceMixin,
    Ec2EvidenceMixin,
    LambdaInventoryEvidenceMixin,
    NetworkEvidenceMixin,
    ResourceTaggingEvidenceMixin,
    S3EvidenceMixin,
    SecurityEvidenceMixin,
    SharedEvidencePrefetchMixin,
)
from unio_collector.scan_workflow.evidence.cost.explorer import (
    SHARED_COST_EXPLORER_DAILY_COST_API_CALLS,
    SHARED_COST_EXPLORER_DAILY_COST_CONSUMERS,
    SHARED_COST_EXPLORER_DAILY_COST_SCANNER_ID,
)
from unio_collector.scan_workflow.evidence.s3 import (
    SHARED_S3_BUCKET_INDEX_API_CALLS,
    SHARED_S3_BUCKET_INDEX_CONSUMERS,
    SHARED_S3_BUCKET_INDEX_SCANNER_ID,
    format_s3_bucket_metadata_label,
)


class ScannerEvidenceCollectionService(
    CostExplorerEvidenceMixin,
    Ec2EvidenceMixin,
    NetworkEvidenceMixin,
    ResourceTaggingEvidenceMixin,
    CloudWatchEvidenceMixin,
    LambdaInventoryEvidenceMixin,
    S3EvidenceMixin,
    SharedEvidencePrefetchMixin,
    SecurityEvidenceMixin,
):
    """Collect and cache shared AWS evidence for scanner execution."""


__all__ = [
    "SHARED_COST_EXPLORER_DAILY_COST_API_CALLS",
    "SHARED_COST_EXPLORER_DAILY_COST_CONSUMERS",
    "SHARED_COST_EXPLORER_DAILY_COST_SCANNER_ID",
    "SHARED_S3_BUCKET_INDEX_API_CALLS",
    "SHARED_S3_BUCKET_INDEX_CONSUMERS",
    "SHARED_S3_BUCKET_INDEX_SCANNER_ID",
    "ScannerEvidenceCollectionService",
    "format_s3_bucket_metadata_label",
]
