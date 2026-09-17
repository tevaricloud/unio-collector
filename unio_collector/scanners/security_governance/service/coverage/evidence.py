from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.regional.security_service_record import (
        RegionalSecurityServiceRecord,
    )


@dataclass(frozen=True)
class SecurityServiceCoverageEvidence:  # noqa: D101
    records: tuple[RegionalSecurityServiceRecord, ...] = ()
    regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
