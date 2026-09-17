from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.kms.key_posture.record import KmsKeyPostureRecord


@dataclass(frozen=True)
class KmsKeyPostureEvidence:  # noqa: D101
    keys: tuple[KmsKeyPostureRecord, ...] = ()
    regions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
