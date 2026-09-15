from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.platform_inventory import ElastiCacheRegionRecord


@dataclass(frozen=True)
class ElastiCacheCostReviewEvidence:  # noqa: D101
    records: list[ElastiCacheRegionRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
