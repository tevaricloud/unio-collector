from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.security_governance.security_hub.control_record import (
        SecurityHubControlRecord,
    )


@dataclass(frozen=True)
class SecurityHubControlSummaryEvidence:  # noqa: D101
    records: tuple[SecurityHubControlRecord, ...] = ()
    regions: tuple[str, ...] = ()
    enabled_regions: tuple[str, ...] = ()
    unavailable_regions: tuple[str, ...] = ()
    not_enabled_regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
