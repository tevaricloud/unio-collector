from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cloudfront.distribution import CloudFrontDistributionRecord


@dataclass(frozen=True)
class CloudFrontOriginCostReviewEvidence:  # noqa: D101
    records: list[CloudFrontDistributionRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=lambda: ["global"])
