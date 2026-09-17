from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.identity_center.instance_record import (
        IdentityCenterInstanceRecord,
    )


@dataclass(frozen=True)
class IdentityCenterEvidence:  # noqa: D101
    instances: tuple[IdentityCenterInstanceRecord, ...] = ()
    warnings: tuple[str, ...] = ()
    account_id: str = "unknown-account"
