from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.scanners.identity_center.permission_set_record import (
        IdentityCenterPermissionSetRecord,
    )


@dataclass(frozen=True)
class IdentityCenterInstanceRecord:  # noqa: D101
    instance_arn: str
    identity_store_id: str | None
    owner_account_id: str | None = None
    name: str | None = None
    status: str | None = None
    created_at: datetime | None = None
    permission_sets: tuple[IdentityCenterPermissionSetRecord, ...] = ()
