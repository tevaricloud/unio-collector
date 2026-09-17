from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.analytics.ai import AthenaRegionRecord


@dataclass(frozen=True)
class AthenaQueryEfficiencyReviewEvidence:  # noqa: D101
    records: list[AthenaRegionRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
