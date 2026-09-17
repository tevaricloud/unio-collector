from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.audit_cost.cloudtrail.trail_record import (
        CloudTrailSecurityTrailRecord,
    )


@dataclass(frozen=True)
class CloudTrailSecurityPostureEvidence:  # noqa: D101
    trails: tuple[CloudTrailSecurityTrailRecord, ...] = ()
    regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    account_id: str = "unknown-account"
    trail_inventory_complete: bool = True
