from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.platform_inventory import EksRegionRecord


@dataclass(frozen=True)
class EksCostRiskReviewEvidence:  # noqa: D101
    records: list[EksRegionRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
