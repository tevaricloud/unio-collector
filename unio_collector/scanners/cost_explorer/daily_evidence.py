from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cost_explorer import DailyCostRecord
    from unio_collector.core.scan.period import ScanPeriod


@dataclass(frozen=True)
class DailyCostEvidence:  # noqa: D101
    records: list[DailyCostRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=lambda: ["global"])
    scan_period: ScanPeriod | None = None
