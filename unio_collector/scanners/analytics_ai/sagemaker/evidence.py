from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.analytics.ai import SageMakerRegionRecord


@dataclass(frozen=True)
class SageMakerCostReviewEvidence:  # noqa: D101
    records: list[SageMakerRegionRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
