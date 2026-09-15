from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.service.coverage.record import ServiceCoverageRecord


@dataclass(frozen=True)
class ServiceCoverageEvidence:  # noqa: D101
    records: list[ServiceCoverageRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    account_id: str = ""
