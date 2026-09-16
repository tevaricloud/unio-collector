from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.s3 import (
        S3BucketLifecycleRecord,
        S3LifecycleCollectionSummary,
    )


@dataclass(frozen=True)
class S3LifecycleEvidence:  # noqa: D101
    records: list[S3BucketLifecycleRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    collection_summary: S3LifecycleCollectionSummary | None = None
    selection_policy_applied: bool = True
    historical_selection_mode: str = "full"
    historical_bucket_limit: int = 25
    historical_include_metric_unknown: bool = True
    historical_conditional_versioning: bool = False
