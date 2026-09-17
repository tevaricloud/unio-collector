from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.security_finding.record import SecurityFindingRecord


@dataclass(frozen=True)
class ActiveSecurityFindingEvidence:  # noqa: D101
    findings: tuple[SecurityFindingRecord, ...] = ()
    regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    collection_evidence_version: int = 0
