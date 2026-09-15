from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.ecr.image_scan.registry_record import EcrRegistryScanRecord
    from unio_collector.scanners.ecr.image_scan.repository_record import (
        EcrRepositoryScanRecord,
    )


@dataclass(frozen=True)
class EcrImageScanPostureEvidence:  # noqa: D101
    repositories: tuple[EcrRepositoryScanRecord, ...] = ()
    registries: tuple[EcrRegistryScanRecord, ...] = ()
    regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    account_id: str = "unknown-account"
