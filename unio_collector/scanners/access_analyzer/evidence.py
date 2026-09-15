from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.access_analyzer.finding_record import (
        AccessAnalyzerFindingRecord,
    )
    from unio_collector.scanners.access_analyzer.record import AccessAnalyzerRecord


@dataclass(frozen=True)
class AccessAnalyzerEvidence:  # noqa: D101
    analyzers: tuple[AccessAnalyzerRecord, ...] = ()
    findings: tuple[AccessAnalyzerFindingRecord, ...] = ()
    regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    collection_evidence_version: int = 0
    analyzer_inventory_status: dict[str, str] = field(default_factory=dict)
