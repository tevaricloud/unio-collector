from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.security_governance.public_exposure.record import (
        PublicServiceExposureRecord,
    )


@dataclass(frozen=True)
class PublicServiceExposureEvidence:  # noqa: D101
    records: tuple[PublicServiceExposureRecord, ...] = ()
    regions: tuple[str, ...] = ()
    global_records: tuple[PublicServiceExposureRecord, ...] = ()
    warnings: tuple[str, ...] = ()
